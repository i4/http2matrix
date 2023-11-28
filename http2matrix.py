#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This module provides an HTTP 2 Matrix message bot

Classes: MessageBot, MessageException
Functions: start(configfile)
"""

from __future__ import annotations
from typing import Pattern
import re
import ssl
import sys
import html
import asyncio
import logging
import logging.config

import yaml
from aiohttp import web
from nio import AsyncClient, responses


__author__ = "Bernhard Heinloth"
__copyright__ = "Copyright 2023, Informatik 4 / FAU"
__license__ = "AGPL"
__version__ = "1.0.0"


class MessageException(Exception):
    """
    Exception message to be delivered to the client
    ...
    Attributes
    ----------
    status : int
        HTTP Status code
    message : str
        The error message which should be displayed on the client
    details : str
        Additional details for the server-side logging
    """

    def __init__(self, status, message, details=None):
        self.status: int = status
        self.message: str = message
        self.details: str | None = details
        super().__init__(self.message)

    def __str__(self):
        append = f" ({self.details})" if self.details else ""
        return f"Status {self.status} - {self.message}{append}"


class MessageBot:
    """
    Bot handling HTTP connections and sending Matrix messages
    ...
    Attributes
    ----------
    default_domain : str
        Default Matrix domain for naked user ids
    access_matrix : dict[str, list[str]]
        Allow/deny list for Matrix user/room recipients
    access_web : dict[str, list[str]]
        Allow/deny list details for HTTP client IPs
    """

    def __init__(
        self,
        default_domain: str | None = None,
        access_matrix: dict[str, list[str]] | None = None,
        access_web: dict[str, list[str]] | None = None,
    ):
        self.client: AsyncClient = None
        self.user: str = ""
        self.room_cache: dict[frozenset[str], str] = {}
        self.domain: str | None = default_domain
        self.snom_fix = re.compile(r"[=](\S.*?\S)([&]|$)", re.IGNORECASE | re.UNICODE)
        if access_matrix:
            self.to_allow = self.get_to_regex(access_matrix.get("allow"))
            self.to_deny = self.get_to_regex(access_matrix.get("deny"))
        if access_web:
            self.ip_allow = self.get_ip_regex(access_web.get("allow"))
            self.ip_deny = self.get_ip_regex(access_web.get("deny"))

    @staticmethod
    def get_ip_regex(ip_list: list[str] = None) -> Pattern | None:
        """Get an RegEx matching the given IP(v4 & 6) wildcard list."""
        if not ip_list or len(ip_list) == 0:
            return None
        valid_ip = re.compile(r"[0-9a-fA-F:.*]")
        regex_list = []
        for ip in ip_list:
            if valid_ip.match(ip):
                regex_list.append(ip.replace(".", "\\.").replace("*", "[0-9a-fA-F:.]+"))
            else:
                logging.warning("%s is not a valid ip - skipping!\n", ip)
        return (
            re.compile(f'^({"|".join(regex_list)})$') if len(regex_list) > 0 else None
        )

    @staticmethod
    def get_to_regex(to_list: list[str] = None) -> Pattern | None:
        """Get an RegEx matching the given Matrix user/room wildcard list."""
        if not to_list or len(to_list) == 0:
            return None
        regex_list = []
        for to in to_list:
            regex_list.append(".*".join([re.escape(regex) for regex in to.split("*")]))
        return (
            re.compile(f'^({"|".join(regex_list)})$') if len(regex_list) > 0 else None
        )

    async def connect(self, homeserver: str, user: str, password: str) -> bool:
        """Connect and login into Matrix"""
        client = AsyncClient(homeserver, user)
        resp = await client.login(password)
        if isinstance(resp, responses.LoginResponse):
            logging.debug("Connected as %s on %s!", user, homeserver)
            self.user = user
            self.client = client
            return True
        else:
            logging.error(
                f"Logging in on {homeserver} as {user} failed: {resp.message} (HTTP STATUS: {resp.transport_response.status})"
            )
            await self.client.close()
            return False

    async def get_room_members(self, room_id: str) -> frozenset[str]:
        """Get all members (joined or at least invited) of a room"""
        members = set()
        resp = await self.client.room_get_state(room_id)
        if isinstance(resp, responses.RoomGetStateResponse) and resp.room_id == room_id:
            for event in resp.events:
                if (
                    "type" in event
                    and event["type"] == "m.room.member"
                    and event["content"]["membership"] in ["invite", "join"]
                ):
                    members.add(event["state_key"])
        else:
            logging.debug("Room %s does not exist anymore: %s", room_id, resp.message)
        return frozenset(members)

    async def send(self, to: str, message: str) -> str:
        """Send a message into an existing or newly created room with the recipient(s)"""
        room: str | None = None
        recipients: list[str] = []
        to = to.strip()
        if not self.client:
            raise MessageException(500, "Not connected to Matrix")
        if not message or len(message) == 0:
            raise MessageException(400, "Message is empty")
        if not to or len(to) == 0:
            raise MessageException(400, "No recipient for message")
        if to[0] in ["#", "!", "*"]:
            # Helper if URL encoding poses some difficulties for public rooms
            if to[0] == "*":
                to = "#" + to[1:]
            # Check if allowed
            if self.to_allow and not self.to_allow.match(to):
                raise MessageException(400, f"Sending message to room {to} not allowed")
            if self.to_deny and self.to_deny.match(to):
                raise MessageException(400, f"Sending message to room {to} denied")
            # resolve room alias
            if to[0] == "#":
                resp = await self.client.room_resolve_alias(to)
                if isinstance(resp, responses.RoomResolveAliasResponse):
                    room = resp.room_id
                    recipients.append(to)
                    logging.debug("Resolved room alias %s to %s", to, room)
                else:
                    raise MessageException(
                        400, f"Room alias {to} could not be resolved"
                    )
            else:
                room = to
                recipients.append(room)
        else:
            # allow multiple users ...
            for user_id in re.split(",|;| ", to):
                user_id = user_id.strip()
                # Missing @
                if user_id[0] != "@":
                    user_id = f"@{user_id}"
                # Missing domain -> use default
                if ":" not in user_id:
                    user_id = f"{user_id}:{self.domain}"
                #  check user
                if self.to_allow and not self.to_allow.match(user_id):
                    raise MessageException(
                        400, f"Sending message to user {user_id} not allowed"
                    )
                if self.to_deny and self.to_deny.match(user_id):
                    raise MessageException(
                        400, f"Sending message to user {user_id} denied"
                    )
                recipients.append(user_id)
            # Required members for room
            members: frozenset[str] = frozenset(recipients + [self.user])
            # ... but prevent mixing with room names!
            if not all(u[0] == "@" for u in recipients):
                raise MessageException(
                    400, "Recipient must be either user(s) or a room"
                )
            # check cache -- and ensure it is sill up to date
            cached_room = self.room_cache.get(members)
            if cached_room and members == await self.get_room_members(cached_room):
                room = cached_room
                logging.debug(
                    "Found room %s for %s in cache", room, ", ".join(list(members))
                )
            else:
                logging.debug("Checking all rooms...")
                # Rebuild cache
                cache = {}
                resp = await self.client.joined_rooms()
                if not isinstance(resp, responses.JoinedRoomsResponse):
                    raise MessageException(500, "Unable to query rooms", resp.message)
                # Check all rooms
                for check_room in resp.rooms:
                    # get all members
                    joined = await self.get_room_members(check_room)
                    if len(joined) == 1 and {self.user} == joined:
                        # Leave and forget room if only bot is member
                        logging.debug("Deleting old room %s", check_room)
                        await self.client.room_leave(check_room)
                        await self.client.room_forget(check_room)
                    else:
                        # Put room into cache
                        cache[joined] = check_room
                        # Check if we have a room
                        if members == joined:
                            room = check_room
                            logging.debug(
                                "Found room %s for %s",
                                check_room,
                                ", ".join(list(members)),
                            )
                # Update dict
                self.room_cache = cache
            # Create new room if none exist
            if not room:
                logging.debug("Creating new room for %s", ", ".join(list(members)))
                resp = await self.client.room_create(is_direct=True, invite=recipients)
                if isinstance(resp, responses.RoomCreateResponse):
                    room = resp.room_id
                    self.room_cache[members] = resp.room_id
                else:
                    raise MessageException(
                        500,
                        "Unable to create new room for " + ", ".join(recipients),
                        resp.message,
                    )
        if room:
            # Join (always)
            resp = await self.client.join(room)
            if not isinstance(resp, responses.JoinResponse):
                raise MessageException(
                    500, "Unable to join room", f"{room}: {resp.message}"
                )
            # send the message
            logging.debug('Sending message "%s" to room %s', message, room)
            await self.client.room_send(
                room_id=room,
                message_type="m.room.message",
                content={"msgtype": "m.text", "body": message},
            )
        else:
            # This should not happen
            raise MessageException(500, "No room available")
        return ", ".join(recipients)

    async def sync(self) -> None:
        """Synchronize with Matrix server."""
        if self.client:
            resp = await self.client.sync(30000)
            if isinstance(resp, responses.SyncResponse):
                logging.debug("Synchronized with token %s", resp.next_batch)
            else:
                logging.warning("Synchronization failed")

    async def disconnect(self) -> None:
        """Logout and disconnect from Matrix server."""
        if self.client:
            logging.debug("Disconnecting matrix")
            await self.client.logout()
            await self.client.close()
            self.client = None

    @staticmethod
    def response(title: str, text: str, code: int = 200) -> web.Response:
        """Create a HTTP response."""
        return web.Response(
            text=f"""<!doctype html>
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
        <div style="font-size:60%;">
            <i>Please note:</i>
            The bot will keep messages in his history – admins may be able to read them.<br>
            To clear the history every other member has to leave the room:
            If the bot detects that he is the only one in the next time he checks the occupants,
            he will leave and forget those messages.
        </div>
    </body>
</html>""",
            status=code,
            content_type="text/html",
        )

    async def process(
        self, to: str | None, message: str | None, client: str | None
    ) -> web.Response:
        """Process a message send HTTP request."""
        if not to or len(to) == 0:
            raise MessageException(400, "Missing recipient in request")
        if not message or len(message) == 0:
            raise MessageException(400, "No message in request")
        try:
            logging.info('Request from %s to send "%s" to "%s"', client, message, to)
            # Check if client is allowed to send request
            if client:
                if self.ip_allow and not self.ip_allow.match(client):
                    raise MessageException(403, f"Client with IP {client} not allowed")
                if self.ip_deny and self.ip_deny.match(client):
                    raise MessageException(403, f"Client with IP {client} denied")
            recipients = await self.send(to, message)
            return self.response(
                "Message sent!",
                f"A message with the content <pre>{html.escape(message)}</pre>"
                f" was sent to <tt>{html.escape(recipients)}</tt>",
            )
        except MessageException as exception:
            logging.warning("Exception: %s", str(exception))
            return self.response(
                "Sending message failed!",
                html.escape(exception.message),
                exception.status,
            )

    async def handle_send(self, request: web.Request) -> web.Response:
        """Handle a '/TO/MSG' HTTP request"""
        return await self.process(
            request.match_info.get("to"),
            request.match_info.get("message"),
            request.remote,
        )

    async def handle_snom(self, request: web.Request) -> web.Response:
        """Handle a '/TO/?MSG=var&' HTTP request"""
        # cleaning snom variables in message which have to be prefixed with '=' and ends with '&'
        return await self.process(
            request.match_info.get("to"),
            self.snom_fix.sub(r"\1", request.query_string),
            request.remote,
        )

    async def handle_landing(self, request: web.Request) -> web.Response:
        """Handle landing page and '/?to=TO&message=MSG' HTTP requests"""
        if "to" in request.query and "message" in request.query:
            return await self.process(
                request.query["to"], request.query["message"], request.remote
            )
        else:
            return self.response(
                "Welcome!",
                """This ist the <b>http2matrix</b> service,
for more details and documentation have a look at the
<a href="https://gitlab.cs.fau.de/i4/infra/http2matrix">project page</a>!
            <h2>Try it</h2>
            <form action="/" method="get">
                <label for="to">To:</label>
                <input type="text" id="to" name="to" placeholder="user(s) or room" title="For users you can either use the full Matrix user ID (e.g., @uj66ojab:fau.de) or just the username (e.g., uj66ojab). Multiple users should be delimited by a comma. In case of a room, you have to always specify the full ID (e.g., #i4:fau.de) neither shortcuts nor sending to multiple rooms is supported."><br>
                <br>
                <label for="message">Message:</label><br>
                <textarea id="message" name="message" rows="4" cols="50">Enter your message here...</textarea><br>
                <br>
                <input type="submit" value="Send">
            </form>""",
            )


async def start(configfile: str) -> None:
    """Setup HTTP server according to configuration file"""
    # Load config file
    with open(configfile, "r", encoding="utf-8") as file:
        settings = yaml.safe_load(file)

    if not settings:
        raise Exception("Config file missing (tried '{configfile}')!")
    if "matrix" not in settings:
        raise Exception("Missing 'matrix' section in config '{configfile}'!")
    if "web" not in settings:
        raise Exception("Missing 'web' section in config '{configfile}'!")

    if "logging" in settings:
        logging.config.dictConfig(settings["logging"])
        logging.debug("Logging configured")

    # Initialize Message bot
    msgbot = MessageBot(
        settings["matrix"].get("domain"),
        settings["matrix"].get("access"),
        settings["web"].get("access"),
    )
    try:
        connected = await msgbot.connect(
            settings["matrix"].get("homeserver"),
            settings["matrix"].get("user"),
            settings["matrix"].get("password"),
        )
        if not connected:
            raise Exception(
                "Unable to log into matrix at "
                f"{settings['matrix'].get('homeserver')} as "
                f"{settings['matrix'].get('user')}!"
            )

        # Preparing web server
        app = web.Application()
        app.add_routes(
            [
                web.get("/", msgbot.handle_landing),
                web.get("/{to}/", msgbot.handle_snom),
                web.get("/{to}/{message}", msgbot.handle_send),
            ]
        )
        runner = web.AppRunner(app)
        await runner.setup()

        # Start endpoints
        endpoints = []
        for service in settings["web"]:
            if service != "access":
                if (
                    "cert" in settings["web"][service]
                    and "key" in settings["web"][service]
                ):
                    logging.debug("Setting up HTTPS service '%s'", service)
                    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    ssl_context.load_cert_chain(
                        settings["web"][service].get("cert"),
                        settings["web"][service].get("key"),
                    )
                else:
                    logging.debug("Setting up HTTP service '%s'", service)
                    ssl_context = None
                endpoint = web.TCPSite(
                    runner,
                    settings["web"][service].get("host"),
                    settings["web"][service].get("port"),
                    ssl_context=ssl_context,
                )
                await endpoint.start()
                endpoints.append(endpoint)

        if len(endpoints) == 0:
            raise Exception("No web endpoint configured in '{configfile}'")

        while True:
            await msgbot.sync()
            await asyncio.sleep(30)

    finally:
        await asyncio.sleep(0)
        if endpoints:
            logging.debug("Stopping endpoints")
            for endpoint in endpoints:
                await endpoint.stop()
        if runner:
            logging.debug("Cleaning up runner")
            await runner.cleanup()
        await msgbot.disconnect()


if __name__ == "__main__":
    asyncio.run(start(sys.argv[1] if len(sys.argv) > 1 else "config.yml"))
