import re
import ssl
import sys
import html
import yaml
import atexit
import asyncio
import logging
from aiohttp import web
from nio import AsyncClient, MatrixRoom, RoomMessageText, responses


class MessageException(Exception):
	def __init__(self, status, message, details = None):
		self.status = status
		self.message = message
		self.details = details
		super().__init__(self.message)

	def __str__(self):
		append = f' ({self.details})' if self.details else ''
		return f'Status {self.status} - {self.message}{append}'


class MessageBot:
	def __init__(self, default_domain = None, access_matrix = None, access_web = None):
		self.client = None
		self.user = None
		self.room_cache = {}
		self.domain = default_domain
		self.snom_fix = re.compile(r'[=](\S.*?\S)([&]|$)', re.IGNORECASE | re.UNICODE)
		if access_matrix:
			self.to_allow = self.get_to_regex(access_matrix.get('allow'))
			self.to_deny = self.get_to_regex(access_matrix.get('deny'))
		if access_web:
			self.ip_allow = self.get_ip_regex(access_web.get('allow'))
			self.ip_deny = self.get_ip_regex(access_web.get('deny'))

		pass


	@staticmethod
	def get_ip_regex(ips = None):
		if not ips or len(ips) == 0:
			return None
		v = re.compile(r'[0-9a-fA-F:.*]')
		l = []
		for i in ips:
			if v.match(i):
				l.append(i.replace('.', '\.').replace('*', '[0-9a-fA-F:.]+'))
			else:
				logging.warning(f'{i} is not a valid ip - skipping!\n')
		return re.compile('^({})$'.format('|'.join(l))) if len(l) > 0 else None


	@staticmethod
	def get_to_regex(tos = None):
		if not tos or len(tos) == 0:
			return None
		l = []
		for t in tos:
			l.append('.*'.join([ re.escape(r) for r in t.split('*') ]))
		return re.compile('^({})$'.format('|'.join(l))) if len(l) > 0 else None


	async def connect(self, homeserver: str, user: str, password: str) -> bool:
		client = AsyncClient(homeserver, user)
		resp = await client.login(password)
		if not isinstance(resp, responses.LoginResponse):
			logging.error(f"Logging in on {homeserver} as {user} failed: {resp.message}")
			await self.client.close()
			return False
		else:
			logging.debug(f"Connected as {user} on {homeserver}!")
			self.user = user
			self.client = client
			return True

	# Get all members (joined or at least invited) of a room
	async def get_room_members(self, room_id: str) -> frozenset[str]:
		members = set()
		resp = await self.client.room_get_state(room_id)
		if isinstance(resp, responses.RoomGetStateResponse):
			for e in resp.events:
				if 'type' in e and e['type'] == 'm.room.member' and e['content']['membership'] in [ 'invite', 'join' ]:
					members.add(e['state_key'])
		else:
			logging.debug(f"Room {r} does not exist anymore: {resp.message}")
		return frozenset(members)


	async def send(self, to, message):
		room = None
		receivers = []
		if not message or len(message) == 0:
			raise MessageException(400, f"Message is empty")
		elif not to or len(to) == 0:
			raise MessageException(400, f"No receiver for message")
		elif to[0] == '!':
			if self.to_allow and not self.to_allow.match(to):
				raise MessageException(400, f"Sending message to room {to} not allowed")
			elif self.to_deny and self.to_deny.match(to):
				raise MessageException(400, f"Sending message to room {to} denied")
			else:
				room = to
				receivers.append(to)
		else:
			# allow multiple users ...
			for o in to.split(','):
				# Missing @
				if o[0] != '@':
					o = f'@{o}'
				# Missing domain -> use default
				if not ':' in o:
					o = f'{o}:{self.domain}'
				if self.to_allow and not self.to_allow.match(o):
					raise MessageException(400, f"Sending message to user {o} not allowed")
				elif self.to_deny and self.to_deny.match(to):
					raise MessageException(400, f"Sending message to user {o} denied")
				else:
					receivers.append(o)

			# Required members for room
			members = frozenset( receivers + [ self.user ] )

			# ... but prevent mixing with room names!
			if not all(u[0] == '@' for u in receivers):
				raise MessageException(400, f"Receiver must be either user(s) or a room")
			else:
				# check cache -- and ensure it is sill up to date
				if members in self.room_cache and members == await self.get_room_members(self.room_cache[members]):
					room = self.room_cache[members]
					logging.debug(f"Found room {room} for {', '.join(list(members))} in cache")
				else:
					logging.debug(f"Checking all rooms...")
					# Rebuild cache
					self.room_cache.clear()
					# Check all rooms
					for r in (await self.client.joined_rooms()).rooms:
						# get all members
						j = await self.get_room_members(r);

						if len(j) == 1 and { me } == j:
							# Leave and forget room if only bot is member
							logging.debug(f"Deleting old room {r}")
							await self.client.room_leave(r)
							await self.client.room_forget(r)
						else:
							# Put room into cache
							self.room_cache[j] = r
							# Check if we have a room
							if members == j:
								room = r
								logging.debug(f"Found room {r} for {', '.join(list(members))}")

				# Create new room if none exist
				if not room:
					resp = await self.client.room_create(is_direct = True, invite = receivers)
					if isinstance(resp, responses.RoomCreateResponse):
						room = resp.room_id
						self.room_cache[members] = room
					else:
						raise MessageException(500, f"Unable to create new room for {', '.join(receivers)}", resp.message)

		if room:
			# Join (always)
			resp = await self.client.join(room)
			if not isinstance(resp, responses.JoinResponse):
				raise MessageException(500, f"Unable to join room", "{room}: {resp.message}")
			# send the message
			await self.client.room_send(
				room_id = room,
				message_type = "m.room.message",
				content = { "msgtype": "m.text", "body": message },
			)
		else:
			# This should not happen
			raise MessageException(500, f"No room available")

		return ', '.join(receivers)


	async def sync(self):
		if self.client:
			resp = await self.client.sync(30000)
			if isinstance(resp, responses.SyncResponse):
				logging.debug(f'Synchronized with token {resp.next_batch}')
			else:
				logging.warning(f'Synchronization failed')


	async def disconnect(self):
		if self.client:
			logging.debug("Disconnecting matrix")
			await self.client.logout()
			await self.client.close()
			self.client = None


	def response(self, title, text, code = 200):
		return web.Response(text=f"""<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>http2matrix</title>
	</head>
	<body{'' if code == 200 else ' style="color: #880000;"'}>
		<h1>{title}</h1>
		<div>{text}</div>
		<br>
		<div><small><i>Please note:</i> The sender <tt></tt> will keep messages in his history – Admins may be able to read them.<br>
		To clear the history every other member has to leave the room: If the sender detects that he is the only one in the next time he checks the occupants, he will leave and forget the messages.</div>
	</body>
</html>""", status=code, content_type='text/html')


	async def process(self, to, message, client):
		try:
			# Check if client is allowed to send request
			if self.ip_allow and not self.ip_allow.match(client):
				raise MessageException(403, f"Client with IP {client} not allowed")
			elif self.ip_deny and self.ip_deny.match(client):
				raise MessageException(403, f"Client with IP {client} denied")
			receivers = await self.send(to, message)

			return self.response('Message send!', f'A message with the content <pre>{html.escape(message)}</pre> was sent to <tt>{html.escape(receivers)}</tt>')
		except MessageException as e:
			logging.warning(str(e))
			return self.response("Sending message failed!", html.escape(e.message), e.status)


	async def handle_send(self, request):
		return await self.process(request.match_info.get('to'), request.match_info.get('message'), request.remote)


	async def handle_snom(self, request):
		# cleaning snom variables in message which have to be prefixed with '=' and ends with '&'
		return await self.process(request.match_info.get('to'), self.snom_fix.sub(r'\1', request.query_string), request.remote)


	async def handle_landing(self, request):
		return self.response('Welcome!', 'This ist the <b>http2matrix</b> service, for more details and documentation have a look at the <a href="https://gitlab.cs.fau.de/i4/infra/http2matrix">project page</a>!')


async def main(configfile):
	# Load config file
	with open(configfile, 'r') as file:
		settings = yaml.safe_load(file)
	if not settings:
		raise Exception("Config file missing (tried '{configfile}')!")
	elif not 'matrix' in settings:
		raise Exception("Missing 'matrix' section in config '{configfile}'!")
	elif not 'web' in settings:
		raise Exception("Missing 'web' section in config '{configfile}'!")

	# Initialize Message bot
	msgbot = MessageBot(settings['matrix'].get('domain'), settings['matrix'].get('access'), settings['web'].get('access'))
	try:
		connected = await msgbot.connect(settings['matrix'].get('homeserver'), settings['matrix'].get('user'), settings['matrix'].get('password'))
		if not connected:
			raise Exception(f"Unable to log into matrix at {settings['matrix'].get('homeserver')} as {settings['matrix'].get('user')}!")

		# Preparing web server
		app = web.Application()
		app.add_routes([
			web.get('/', msgbot.handle_landing),
			web.get('/{to}/', msgbot.handle_snom),
			web.get('/{to}/{message}', msgbot.handle_send)
		])
		runner = web.AppRunner(app)
		await runner.setup()

		# Start endpoints
		endpoints = []
		for s in settings['web']:
			if s != 'access':
				if 'cert' in settings['web'][s] and 'key' in settings['web'][s]:
					logging.debug(f"Setting up HTTPS service '{s}'")
					ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
					ssl_context.load_cert_chain(settings['web'][s].get('cert'), settings['web'][s].get('key'))
				else:
					logging.debug(f"Setting up HTTP service '{s}'")
					ssl_context = None
				e = web.TCPSite(runner, settings['web'][s].get('host'), settings['web'][s].get('port'), ssl_context = ssl_context)
				await e.start()
				endpoints.append(e)

		if len(endpoints) == 0:
			raise Exception("No web endpoint configured in '{configfile}'")

		while True:
			await msgbot.sync()
			await asyncio.sleep(30)

	finally:
		await asyncio.sleep(0)
		if endpoints:
			logging.debug("Stopping endpoints")
			for e in endpoints:
				await e.stop()
		if runner:
			logging.debug("Cleaning up runner")
			await runner.cleanup()
		await msgbot.disconnect()


if __name__ == '__main__':
	#logging.basicConfig(level=logging.DEBUG)
	asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else 'config.yml'))

