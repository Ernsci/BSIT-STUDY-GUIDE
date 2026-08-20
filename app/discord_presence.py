"""Maintain a persistent Discord gateway connection so the bot shows a custom
status (e.g. Do Not Disturb) and activity ("Playing with a dildo").

The rest of the app talks to Discord over REST, so without this the bot never
connects to the gateway and would otherwise appear offline.
"""

import asyncio
import json
import threading

import websockets

from . import config

GATEWAY = "wss://gateway.discord.gg/?v=10&encoding=json"


def _identify():
    status = (config.DISCORD_PRESENCE_STATUS or "dnd").lower()
    activity = (config.DISCORD_PRESENCE_ACTIVITY or "").strip()
    return {
        "op": 2,
        "d": {
            "token": config.DISCORD_BOT_TOKEN,
            "intents": 0,
            "properties": {
                "$os": "linux",
                "$browser": "DocumentsForNerds",
                "$device": "DocumentsForNerds",
            },
            "presence": {
                "status": status,
                "afk": False,
                "since": 0,
                "activities": (
                    []
                    if not activity
                    else [{"name": activity, "type": 0, "state": "Documents for Nerds"}]
                ),
            },
        },
    }


async def _heartbeat(ws, interval):
    try:
        while True:
            await asyncio.sleep(interval)
            await ws.send(json.dumps({"op": 1, "d": None}))
    except Exception:
        return


async def _run():
    while True:
        try:
            async with websockets.connect(GATEWAY) as ws:
                hello = json.loads(await ws.recv())
                if hello.get("op") != 10:
                    print(f"DISCORD PRESENCE: unexpected hello {hello.get('op')}")
                    raise ConnectionError("bad hello")
                interval = hello["d"]["heartbeat_interval"] / 1000
                await ws.send(json.dumps(_identify()))
                hb = asyncio.create_task(_heartbeat(ws, interval))
                while True:
                    msg = json.loads(await ws.recv())
                    op = msg.get("op")
                    if op == 1:  # heartbeat request from Discord
                        await ws.send(json.dumps({"op": 1, "d": None}))
                    elif op == 7:  # reconnect requested
                        break
                    elif op == 9:  # invalid session
                        print(f"DISCORD PRESENCE: invalid session {msg.get('d')}")
                        break
                    elif op == 11:  # heartbeat ack
                        pass
                    elif op == 0 and msg.get("t") == "READY":
                        print("DISCORD PRESENCE: ready")
                hb.cancel()
        except Exception as exc:
            print(f"DISCORD PRESENCE: {type(exc).__name__}: {exc}")
        await asyncio.sleep(5)


def start():
    if not config.DISCORD_BOT_TOKEN:
        return

    def _spawn():
        asyncio.run(_run())

    t = threading.Thread(target=_spawn, daemon=True, name="discord-presence")
    t.start()