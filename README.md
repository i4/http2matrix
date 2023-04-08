HTTP2Matrix
===========

A small bot forwarding a message to Matrix user(s) / room on a HTTP(S) request.

It allows the integration of older, existing devices in our modern work environment, for example delivering a message about a missed call on the old *snom 320 VoIP* telephone to ones Matrix account (via its [Action URLs](https://service.snom.com/display/wiki/Action+URLs)):

Requesting

	https://example.org/%40user:matrix.org/Hello%20world

will send the message "Hello world" to `@user:matrix.org`.


Prerequisites
-------------

This bot is written in Python 3 using [matrix-nio](https://matrix-nio.readthedocs.io/) and [aiohttp](https://docs.aiohttp.org/).
If you use a recent Debian or Ubuntu, you can install the required dependencies using

	apt install python3-matrix-nio python3-aiohttp python3-yaml

or by using [pip](https://pip.pypa.io/) and the enclosed `requirements.txt` file

	pip install -r requirements.txt


Install
-------

Clone this repository in a local directory (like `/opt/http2matrix/`)

	git clone https://gitlab.cs.fau.de/i4/infra/http2matrix.git /opt/http2matrix

Create a `config.yml` file by adjusting the [example](config-example.yml).
You should use a separate account for the Matrix bot and enter its credentials.

If you want to use HTTPS, get a certificate -- or, for testing purposes, create your own self-signed one:

	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365

Make sure to use the `access` mechanism to both restrict clients being able to make a request and limiting users/rooms which are allowed to be sent messages to.
Otherwise this will be an El Dorado for spam systems!

Start your server with

	python3 http2matrix.py config.yml

or use *systemd* to manage it as a service:

	sudo -s
	cp http2matrix.service /etc/systemd/system/
	systenmctl daemon-reload
	systemctl enable http2matrix
	systemctl start http2matrix

You should now be able to use your webbrowser to connect to your system.
Debug logging might help to find issues.


Usage
-----

Due to several annoying limitations in older systems, this bot provides multiple ways for a request:

	http://example.org/?to=TO&message=MESSAGE
	http://example.org/TO?MESSAGE
	http://example.org/TO/?MESSAGE
	http://example.org/TO/MESSAGE

where **TO** can be a room, one or multiple users:
For users you can either use the full Matrix user ID (e.g., `@uj66ojab:fau.de`) or just the username (e.g., `uj66ojab`).
In the latter case, the Matrix user ID will be generated using the configured default domain.
Multiple users should be delimited by a comma (but semicolon and space will work as well)
In case of a room, you have to always specify the full (alias) ID (e.g., `#i4:fau.de`) - but neither shortcuts nor sending to multiple rooms is supported.

URLs (including **TO** and **MESSAGE**) should be [encoded according to the standard](https://en.wikipedia.org/wiki/URL_encoding), e.g. using `%40` for `@` in user and `%23` for `#`  in room prefixes.
Since the hash character is used for anchors as well, the `*` character can be used instead for referencing room aliases (e.g., `*i4:fau.de`).


Internals
---------

Since Matrix has, unlike XMPP, no native direct messages but uses rooms, the bot will investigate all rooms it has joined.
If the bot and all receivers of a message are either joined or invited in a room, but not anyone else, the message will be delivered to this room.
The part with invited users makes the code a bit more complex but is crucial to ensure that for subsequent messages the same room will be used again, even if a user hasn't joined yet.
In case a user has left, a message targeting him as well will result in creating a new room and inviting all other receivers (if any).

**Please note:** The bot will keep the messages in his history – and hence admins may be able to read them.
To clear the history every other member has to leave the room:
If the bot detects that he is the only one in the next time he checks the occupants, he will leave and forget those messages.

However, there are still other ways that messages are stored on the server (like debug logging), hence be careful about private messages if you do not own and control the server.
