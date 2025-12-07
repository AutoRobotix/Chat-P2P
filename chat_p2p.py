from udp_plus import UDP_Plus
from db import ChatDB as db
from cipher import AES, ECC
import asyncio
import numpy as np
import time

CMD_MESSAGE = b'0'    # message = cmd + address + encrypted ( signature ( data + timestamp ) )
CMD_EXCHANGE = b'1'   # exchange = cmd + signature ( address + ephemeral_pubkey )
CMD_HANDSHAKE = b'2'  # handshake = cmd + key_id + encrypted ( address + peer_pubkey ) 

###  ADD FAIL BUCKET IN UDP_PLUS

class Chat:

    def __init__(self):
        self.address = ''
        self.udp_plus = UDP_Plus('127.0.0.1', 25252)
        self.db = db()
        
        self.peers = {'id': [], 'nickname': [], 'address': []}
        for peer in self.db.get_peers():
            self.peers['id'].append(peer[0])
            self.peers['nickname'].append(peer[1])
            self.peers['address'].append(peer[2])

        self.pending_exchange = {}

    ### --- INPUT --- ###

    async def send_message(self, peer_ip, message):
        return await self.udp_plus.put_message(peer_ip, 25252, message)

    async def _recv_message_task(self):
        while True:
            peer_address, message, timestamp = await self.udp_plus.get_message()
            await self.dispatcher(peer_address, message, timestamp)

    ### --- RECV HANDLERS --- ###

    async def dispatcher(self, peer_address, message, timestamp):
        cmd, message = message[:1], message[1:]

        if cmd == CMD_MESSAGE:
            self.message_handler(peer_address, message)

        elif cmd == CMD_EXCHANGE:
            self.exchange_handler(message)
        
        elif cmd == CMD_HANDSHAKE:
            await self.handshake_handler(message)
        
    def message_handler(self, peer_address, message):
        if peer_address in self.peers['address']:
            index = self.peers['address'].index(peer_address)

            pubkey, sharedkey, expiration = self.db.get_peer('id', self.peers['id'][index], {'pubkey', 'sharedkey', 'expiration'})

            if pubkey and sharedkey and expiration:
                if time.time() < expiration:

                    try:
                        message = AES().decrypt(sharedkey, message)
                        signature, message = message[:64], message[64:]
                        if ECC().verify(pubkey, signature, message):
                            self.db.update_chat(self.peers['id'][index], 'self', message.decode('utf-8'))
                        else: 
                            print('Invalid message signature')
                    except:
                        print('Decryption failed')

    async def exchange_handler(self, message):
        signature, peer_address, peer_ephemeral = message[:64], message[64:], message[64+len(peer_address):]

        if peer_address in self.peers['address']:
            peer_pubkey = self.db.get_peer('address', peer_address, {'pubkey'})

            if peer_pubkey:
                if ECC().verify(peer_pubkey, signature, peer_address + peer_ephemeral):

                    if not self.pending_exchange.get(peer_address):
                        privkey, pubkey = ECC().gen_keypair()
                        sharedkey = ECC().gen_sharedkey(privkey, peer_ephemeral)
                        expiration = time.time() + 86400  # 24 hours
                        signature = ECC().sign(privkey, self.address + pubkey)
                        response = CMD_EXCHANGE + signature + self.address + pubkey
                    
                        if await self.send_message(peer_address, response):
                            self.db.update_peer('address', peer_address, {'sharedkey', 'expiration'}, (sharedkey, expiration))

                    else:
                        privkey = self.pending_exchange[peer_address]['privkey']
                        sharedkey = ECC().gen_sharedkey(privkey, peer_ephemeral)
                        expiration = time.time() + 86400  # 24 hours
                        self.db.update_peer('address', peer_address, {'sharedkey', 'expiration'}, (sharedkey, expiration))
                        del self.pending_exchange[peer_address]

                else:
                    print('Invalid exchange signature')

    async def handshake_handler(self, message):
        key_id, message = message[:8], message[8:]
        primarykey, expiration = self.db.get_primary_key(key_id)

        if primarykey and expiration < time.time():
            try:
                peer_address, peer_pubkey = AES().decrypt(primarykey, message) ### split to do

                if not self.db.get_peer('address', peer_address, {'id'}):
                    privkey, pubkey = ECC.gen_keypair()
                    response = CMD_HANDSHAKE + self.address + AES().encrypt(primarykey, pubkey)

                    if await self.send_message(peer_address, response):
                        self.db.set_peer(None, peer_address, peer_pubkey, privkey, None, 0)
                        id = self.db.get_peer('address', peer_address, {'id'})
                        self.peers['id'].append(id)
                        self.peers['nickname'].append(None)
                        self.peers['address'].append(peer_address)
                        self.db.delete_primary_key(key_id)

                else:
                    self.db.update_peer('address', peer_address, {'pubkey'}, (peer_pubkey,))
                    id = self.db.get_peer('address', peer_address, {'id'})
                    self.peers['id'].append(id)
                    self.peers['nickname'].append(None)
                    self.peers['address'].append(peer_address)
                    self.db.delete_primary_key(key_id)

            except:
                print('Incomplete handshake')

    ### --- SEND HANDLERS --- ###

    async def message_sender(self, peer_address, message):
        if peer_address in self.peers['address']:
            privkey, sharedkey, expiration = self.db.get_peer('address', peer_address, {'privkey', 'sharedkey', 'expiration'})

            if privkey and sharedkey and expiration:
                if time.time() < expiration:
                    signature = ECC().sign(privkey, message)
                    message = AES().encrypt(sharedkey, signature + message)
                    message = CMD_MESSAGE + message
                    return await self.send_message(peer_address, message)
                else:
                    self.db.set_pending(peer_address, message, time.time())
        return False

    async def exchange_sender(self, peer_address):
        ephemeral_privkey, ephemeral_pubkey = ECC().gen_keypair()
        privkey = self.db.get_peer('address', peer_address, {'privkey'}) 
        signature = ECC().sign(privkey, peer_address + ephemeral_pubkey)
        message = CMD_EXCHANGE + signature + peer_address + ephemeral_pubkey

        if await self.message_sender(peer_address, message):
            self.pending_exchange[peer_address] = {'privkey': ephemeral_privkey, 'timestamp': time.time()}

    async def handshake_sender(self, primary_key):
        key_id, address, primarykey, expiration = primary_key[:8], primary_key[8:40], primary_key[40:72], primary_key[72:]
        self.db.set_primary_key(key_id, address, primarykey, expiration)
        pubkey, privkey = ECC().gen_keypair()
        message = CMD_HANDSHAKE + key_id + AES().encrypt(primarykey, self.address + pubkey)
        if await self.message_sender(address, message):
            self.db.set_peer(None, address, None, privkey, None, 0)