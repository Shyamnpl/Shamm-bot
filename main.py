# --- START OF FILE main.py --- #

import requests , os , psutil , sys , jwt , pickle , json , binascii , time , urllib3 , base64 , datetime , re , socket , threading , ssl , pytz , aiohttp
from protobuf_decoder.protobuf_decoder import Parser
from xC4 import * ; from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from Pb2 import DEcwHisPErMsG_pb2 , MajoRLoGinrEs_pb2 , PorTs_pb2 , MajoRLoGinrEq_pb2 , sQ_pb2 , Team_msg_pb2
from cfonts import render, say


#EMOTES BY PARAHEX X CODEX



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# --- BOT STATE MANAGEMENT VARIABLES --- #
bot_role = "idle"  # Can be "idle", "leader", "member"
squad_leader_uid = None
squad_members = []
is_in_match = False
current_game_mode = None # To remember which mode to restart
# ------------------------------------ #

online_writer = None
whisper_writer = None
spam_room = False
spammer_uid = None
spam_chat_id = None
spam_uid = None
Spy = False
Chat_a = False
#------------------------------------------#

Hr = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/x-www-form-urlencoded",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB51"}

# ---- Random Colores ----
def get_random_color():
    colors = [
        "[FF0000]", "[00FF00]", "[0000FF]", "[FFFF00]", "[FF00FF]", "[00FFFF]", "[FFFFFF]", "[FFA500]",
        "[A52A2A]", "[800080]", "[000000]", "[808080]", "[C0C0C0]", "[FFC0CB]", "[FFD700]", "[ADD8E6]",
        "[90EE90]", "[D2691E]", "[DC143C]", "[00CED1]", "[9400D3]", "[F08080]", "[20B2AA]", "[FF1493]",
        "[7CFC00]", "[B22222]", "[FF4500]", "[DAA520]", "[00BFFF]", "[00FF7F]", "[4682B4]", "[6495ED]",
        "[5F9EA0]", "[DDA0DD]", "[E6E6FA]", "[B0C4DE]", "[556B2F]", "[8FBC8F]", "[2E8B57]", "[3CB371]",
        "[6B8E23]", "[808000]", "[B8860B]", "[CD5C5C]", "[8B0000]", "[FF6347]", "[FF8C00]", "[BDB76B]",
        "[9932CC]", "[8A2BE2]", "[4B0082]", "[6A5ACD]", "[7B68EE]", "[4169E1]", "[1E90FF]", "[191970]",
        "[00008B]", "[000080]", "[008080]", "[008B8B]", "[B0E0E6]", "[AFEEEE]", "[E0FFFF]", "[F5F5DC]",
        "[FAEBD7]"
    ]
    return random.choice(colors)

async def encrypted_proto(encoded_hex):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(encoded_hex, AES.block_size)
    encrypted_payload = cipher.encrypt(padded_message)
    return encrypted_payload
    
async def GeNeRaTeAccEss(uid , password):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": (await Ua()),
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=Hr, data=data) as response:
            if response.status != 200: return "Failed to get access token"
            data = await response.json()
            open_id = data.get("open_id")
            access_token = data.get("access_token")
            return (open_id, access_token) if open_id and access_token else (None, None)

async def EncRypTMajoRLoGin(open_id, access_token):
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = str(datetime.now())[:-7]
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.118.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    memory_available = major_login.memory_available
    memory_available.version = 55
    memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019118695"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    string = major_login.SerializeToString()
    return  await encrypted_proto(string)

async def MajorLogin(payload):
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def GetLoginData(base_url, payload, token):
    url = f"{base_url}/GetLoginData"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    Hr['Authorization']= f"Bearer {token}"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, data=payload, headers=Hr, ssl=ssl_context) as response:
            if response.status == 200: return await response.read()
            return None

async def DecRypTMajoRLoGin(MajoRLoGinResPonsE):
    proto = MajoRLoGinrEs_pb2.MajorLoginRes()
    proto.ParseFromString(MajoRLoGinResPonsE)
    return proto

async def DecRypTLoGinDaTa(LoGinDaTa):
    proto = PorTs_pb2.GetLoginData()
    proto.ParseFromString(LoGinDaTa)
    return proto

async def DecodeWhisperMessage(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = DEcwHisPErMsG_pb2.DecodeWhisper()
    proto.ParseFromString(packet)
    return proto
    
async def decode_team_packet(hex_packet):
    packet = bytes.fromhex(hex_packet)
    proto = sQ_pb2.recieved_chat()
    proto.ParseFromString(packet)
    return proto
    
async def xAuThSTarTuP(TarGeT, token, timestamp, key, iv):
    uid_hex = hex(TarGeT)[2:]
    uid_length = len(uid_hex)
    encrypted_timestamp = await DecodE_HeX(timestamp)
    encrypted_account_token = token.encode().hex()
    encrypted_packet = await EnC_PacKeT(encrypted_account_token, key, iv)
    encrypted_packet_length = hex(len(encrypted_packet) // 2)[2:]
    if uid_length == 9: headers = '0000000'
    elif uid_length == 8: headers = '00000000'
    elif uid_length == 10: headers = '000000'
    elif uid_length == 7: headers = '000000000'
    else: print('Unexpected length') ; headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{encrypted_packet_length}{encrypted_packet}"
     
async def cHTypE(H):
    if not H: return 'Squid'
    elif H == 1: return 'CLan'
    elif H == 2: return 'PrivaTe'
    
async def SEndMsG(H , message , Uid , chat_id , key , iv):
    TypE = await cHTypE(H)
    if TypE == 'Squid': msg_packet = await xSEndMsgsQ(message , chat_id , key , iv)
    elif TypE == 'CLan': msg_packet = await xSEndMsg(message , 1 , chat_id , chat_id , key , iv)
    elif TypE == 'PrivaTe': msg_packet = await xSEndMsg(message , 2 , Uid , Uid , key , iv)
    return msg_packet

async def SEndPacKeT(OnLinE , ChaT , TypE , PacKeT):
    if TypE == 'ChaT' and ChaT: whisper_writer.write(PacKeT) ; await whisper_writer.drain()
    elif TypE == 'OnLine' and OnLinE: online_writer.write(PacKeT) ; await online_writer.drain()
    else: return 'UnsoPorTed TypE ! >> ErrrroR (:():)' 

# --- Function to handle the game starting process with game mode --- #
async def start_squad_game(game_mode, key, iv, region, login_data):
    global bot_role, squad_members, online_writer, whisper_writer, is_in_match
    
    if bot_role != "leader":
        return

    print(f"[LEADER] Starting the squad game process for mode: {game_mode}...")
    clan_id = login_data.Clan_ID

    # 1. Leader creates a squad
    print("[LEADER] Creating new squad...")
    create_squad_packet = await OpEnSq(key, iv, region)
    await SEndPacKeT(online_writer, whisper_writer, 'OnLine', create_squad_packet)
    await asyncio.sleep(3) 

    # 2. Leader invites all members
    for member_uid in squad_members:
        print(f"[LEADER] Inviting member: {member_uid}")
        invite_packet = await SEnd_InV(5, member_uid, key, iv, region) 
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', invite_packet)
        await asyncio.sleep(1)
        
    # 3. Wait for members to join
    print("[LEADER] Waiting 10 seconds for members to join...")
    await asyncio.sleep(10)
    
    # 4. Start the game based on the selected mode
    start_game_packet = None
    if game_mode == "cs":
        print("[LEADER] Starting Clash Squad match!")
        start_game_packet = await STarT_GaME_CS(key, iv, region)
    # Add other game modes here later, e.g., elif game_mode == "br":
    
    if start_game_packet:
        await SEndPacKeT(online_writer, whisper_writer, 'OnLine', start_game_packet)
        is_in_match = True
        message = f"[B][C]{get_random_color()}All bots in squad. Starting {game_mode.upper()} match now!"
        P = await SEndMsG(1, message, clan_id, clan_id, key, iv)
        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)
    else:
        print(f"[ERROR] Unknown game mode: {game_mode}")
           
async def TcPOnLine(ip, port, key, iv, AutHToKen, reconnect_delay=0.5):
    global online_writer, whisper_writer, bot_role, is_in_match, current_game_mode
    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            online_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            online_writer.write(bytes_payload)
            await online_writer.drain()
            while True:
                data2 = await reader.read(9999)
                if not data2: break
                
                # --- Logic for re-starting game --- #
                try:
                    packet_hex = data2.hex()
                    # Packet '2c...' often means returning to lobby.
                    if packet_hex.startswith(('2c00', '2c01')) and bot_role == "leader" and is_in_match:
                        is_in_match = False 
                        print("[INFO] Match ended. Bot is back in lobby. Restarting process in 20 seconds.")
                        
                        clan_id = LoGinDaTaUncRypTinG.Clan_ID
                        message = f"[B][C]{get_random_color()}Match finished. Starting new game in 20 seconds..."
                        P = await SEndMsG(1, message, clan_id, clan_id, key, iv)
                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)
                        
                        await asyncio.sleep(20)
                        
                        # Re-run the start game logic with the last used game mode
                        if current_game_mode:
                            await start_squad_game(current_game_mode, key, iv, region, LoGinDaTaUncRypTinG)
                except Exception:
                    pass
                # ---------------------------------- #

            online_writer.close() ; await online_writer.wait_closed() ; online_writer = None

        except Exception as e: print(f"- ErroR With {ip}:{port} - {e}") ; online_writer = None
        await asyncio.sleep(reconnect_delay)
                            
async def TcPChaT(ip, port, AutHToKen, key, iv, LoGinDaTaUncRypTinG, ready_event, region , reconnect_delay=0.5):
    print(region, 'TCP CHAT')

    global whisper_writer, online_writer
    global bot_role, squad_leader_uid, squad_members, TarGeT, current_game_mode

    while True:
        try:
            reader , writer = await asyncio.open_connection(ip, int(port))
            whisper_writer = writer
            bytes_payload = bytes.fromhex(AutHToKen)
            whisper_writer.write(bytes_payload)
            await whisper_writer.drain()
            ready_event.set()
            if LoGinDaTaUncRypTinG.Clan_ID:
                clan_id = LoGinDaTaUncRypTinG.Clan_ID
                clan_compiled_data = LoGinDaTaUncRypTinG.Clan_Compiled_Data
                print(f'\n - Bot Connected to Clan Chat: {clan_id}')
                pK = await AuthClan(clan_id , clan_compiled_data , key , iv)
                if whisper_writer: whisper_writer.write(pK) ; await whisper_writer.drain()
            
            while True:
                data = await reader.read(9999)
                if not data: break
                
                if data.hex().startswith("120000"):
                    packet_hex_data = data.hex()[10:]
                    msg_json = None
                    try:
                        decoded_msg = await DeCode_PackEt(packet_hex_data)
                        if decoded_msg:
                            msg_json = json.loads(decoded_msg)
                    except Exception:
                        pass 

                    response = None
                    try:
                        response = await DecodeWhisperMessage(packet_hex_data)
                    except Exception:
                        pass 

                    if response:
                        uid = response.Data.uid
                        chat_id = response.Data.Chat_ID
                        chat_type = response.Data.chat_type
                        inPuTMsG = response.Data.msg.lower().strip()

                        # --- Squad Game Command with Game Mode --- #
                        game_mode_to_start = None
                        if inPuTMsG.startswith("/s_cs ") and chat_type == 1:
                            game_mode_to_start = "cs"
                        # Add other modes here like:
                        # elif inPuTMsG.startswith("/s_br ") and chat_type == 1:
                        #     game_mode_to_start = "br"

                        if game_mode_to_start:
                            parts = inPuTMsG.split()
                            if len(parts) < 2:
                                message = f"[B][C][FF0000]Usage: /{game_mode_to_start} <leader_uid> <member_uids>..."
                                P = await SEndMsG(1, message, chat_id, chat_id, key, iv)
                                await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)
                                continue

                            try:
                                involved_uids = [int(p) for p in parts[1:]]
                                leader_uid = involved_uids[0]
                                member_uids = involved_uids[1:]
                                
                                if TarGeT in involved_uids:
                                    squad_leader_uid = leader_uid
                                    squad_members = member_uids
                                    current_game_mode = game_mode_to_start # Remember the mode

                                    if TarGeT == leader_uid:
                                        bot_role = "leader"
                                        print(f"[ROLE] This bot ({TarGeT}) is the LEADER for {game_mode_to_start.upper()}.")
                                        message = f"[B][C]{get_random_color()}Acknowledged. I am LEADER. Starting {game_mode_to_start.upper()}..."
                                        P = await SEndMsG(1, message, chat_id, chat_id, key, iv)
                                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)
                                        await start_squad_game(game_mode_to_start, key, iv, region, LoGinDaTaUncRypTinG)
                                    
                                    elif TarGeT in member_uids:
                                        bot_role = "member"
                                        print(f"[ROLE] This bot ({TarGeT}) is a MEMBER. Waiting for invite.")
                                        message = f"[B][C]{get_random_color()}Acknowledged. I am a MEMBER."
                                        P = await SEndMsG(1, message, chat_id, chat_id, key, iv)
                                        await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

                            except ValueError:
                                message = f"[B][C][FF0000]Invalid UID. Please use numbers only."
                                P = await SEndMsG(1, message, chat_id, chat_id, key, iv)
                                await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)
                        
                        elif inPuTMsG.startswith("/g "):
                            try:
                                parts = inPuTMsG.split()
                                if len(parts) > 1 and parts[1].isdigit():
                                    guild_id = int(parts[1])
                                    message = f"[B][C]{get_random_color()}Sending join request to Guild ID: {guild_id}"
                                    P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                                    await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)
                                    GuildPacket = await JoIn_GuiLD(guild_id, key, iv)
                                    await SEndPacKeT(online_writer, whisper_writer, 'OnLine', GuildPacket)
                            except Exception as e:
                                print(f"Error processing /g command: {e}")

                        elif inPuTMsG.startswith('/x/'):
                            CodE = inPuTMsG.split('/x/')[1]
                            EM = await GenJoinSquadsPacket(CodE , key , iv)
                            await SEndPacKeT(online_writer, whisper_writer, 'OnLine' , EM)

                        elif inPuTMsG.startswith('@a '):
                            try:
                                parts = inPuTMsG.split()
                                target_uid = int(parts[1])
                                emote_id = int(parts[2])
                                H = await Emote_k(target_uid, emote_id, key, iv, region)
                                await SEndPacKeT(online_writer, whisper_writer, 'OnLine', H)
                            except (IndexError, ValueError):
                                message = f"[B][C][FF0000]Usage: @a <target_uid> <emote_id>"
                                P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                                await SEndPacKeT(online_writer, whisper_writer, 'ChaT', P)

                        elif inPuTMsG in ("hi", "hello", "help", "/help"):
                            message = (
                                f"[B]MG24 AUTOMATION BOT\n"
                                f"[00FF00]OWNER: MG24 GAMER\n\n"
                                f"[FFFF00]Auto-Game Commands (Guild Only):\n"
                                f"[FFFFFF]/s_cs <leader> <m1>... - Start Clash Squad\n\n"
                                f"[FFFF00]Other Commands:\n"
                                f"/help - Shows this message.\n"
                                f"/g <guild_id> - Send guild join request.\n"
                                f"@a <uid> <emote_id> - Activate emote.\n"
                                f"/x/<team_code> - Join a team by code."
                            )
                            P = await SEndMsG(chat_type, message, uid, chat_id, key, iv)
                            await SEndPacKeT(online_writer, whisper_writer, 'ChaT' , P)
                    
                    if bot_role == "member" and squad_leader_uid is not None and msg_json:
                        try:
                            if '5' in msg_json and 'data' in msg_json['5'] and '16' in msg_json['5']['data']:
                                inviter_uid = msg_json['5']['data']['1']['data']
                                if inviter_uid == squad_leader_uid:
                                    squad_code_to_join = msg_json['5']['data']['31']['data']
                                    print(f"[MEMBER] Received invite from leader. Joining squad {squad_code_to_join}...")
                                    join_packet = await GenJoinSquadsPacket(squad_code_to_join, key, iv)
                                    await SEndPacKeT(online_writer, whisper_writer, 'OnLine', join_packet)
                                    bot_role = "idle" 
                                    squad_leader_uid = None
                        except KeyError:
                            pass 
                            
            whisper_writer.close() ; await whisper_writer.wait_closed() ; whisper_writer = None
        except Exception as e: print(f"ErroR {ip}:{port} - {e}") ; whisper_writer = None
        await asyncio.sleep(reconnect_delay)

async def MaiiiinE():
    global TarGeT, LoGinDaTaUncRypTinG, region, key, iv 
    Uid , Pw = '4266639041','B5454E6CCF4E07071197BD61957847DEC791F6C8F7468B4B530D926924A61D73'
    
    open_id , access_token = await GeNeRaTeAccEss(Uid , Pw)
    if not open_id or not access_token: print("ErroR - InvaLid AccounT") ; return None
    
    PyL = await EncRypTMajoRLoGin(open_id , access_token)
    MajoRLoGinResPonsE = await MajorLogin(PyL)
    if not MajoRLoGinResPonsE: print("TarGeT AccounT => BannEd / NoT ReGisTeReD ! ") ; return None
    
    MajoRLoGinauTh = await DecRypTMajoRLoGin(MajoRLoGinResPonsE)
    UrL = MajoRLoGinauTh.url
    region = MajoRLoGinauTh.region
    ToKen = MajoRLoGinauTh.token
    TarGeT = MajoRLoGinauTh.account_uid
    key = MajoRLoGinauTh.key
    iv = MajoRLoGinauTh.iv
    timestamp = MajoRLoGinauTh.timestamp
    
    LoGinDaTa = await GetLoginData(UrL , PyL , ToKen)
    if not LoGinDaTa: print("ErroR - GeTinG PorTs From LoGin DaTa !") ; return None
    LoGinDaTaUncRypTinG = await DecRypTLoGinDaTa(LoGinDaTa)
    OnLinePorTs = LoGinDaTaUncRypTinG.Online_IP_Port
    ChaTPorTs = LoGinDaTaUncRypTinG.AccountIP_Port
    OnLineiP , OnLineporT = OnLinePorTs.split(":")
    ChaTiP , ChaTporT = ChaTPorTs.split(":")
    acc_name = LoGinDaTaUncRypTinG.AccountName
    equie_emote(ToKen,UrL)
    AutHToKen = await xAuThSTarTuP(int(TarGeT) , ToKen , int(timestamp) , key , iv)
    ready_event = asyncio.Event()
    
    task1 = asyncio.create_task(TcPChaT(ChaTiP, ChaTporT , AutHToKen , key , iv , LoGinDaTaUncRypTinG , ready_event ,region))
     
    await ready_event.wait()
    await asyncio.sleep(1)
    task2 = asyncio.create_task(TcPOnLine(OnLineiP , OnLineporT , key , iv , AutHToKen))
    os.system('clear')
    print(render('MG24 GMR.', colors=['white', 'red'], align='center'))
    print('')
    print(f" - BoT STarTinG And OnLine on TarGet : {TarGeT} | BOT NAME : {acc_name}\n")
    print(f" - BoT sTaTus > GooD | OnLinE ! (:")    
    print(f" - Subscribe > YOUTUBE | MG24 GAMER ! (:")    
    await asyncio.gather(task1 , task2)
    
async def StarTinG():
    while True:
        try: await asyncio.wait_for(MaiiiinE() , timeout = 7 * 60 * 60)
        except asyncio.TimeoutError: print("Token ExpiRed ! , ResTartinG")
        except Exception as e: print(f"ErroR TcP - {e} => ResTarTinG ...")

if __name__ == '__main__':
    asyncio.run(StarTinG())