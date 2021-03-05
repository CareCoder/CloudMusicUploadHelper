import pyncm
import getpass
import hashlib
import tinytag
import sys
import binascii
import struct
import base64
import json
import os
import time
import qrcode
from Crypto.Cipher import AES
from pyncm import GetCurrentSession, LoadSessionFromString
from pyncm.apis.login import GetCurrentLoginStatus, WriteLoginInfo

SESSION_FILE = os.getenv("APPDATA") + "\\ncm_cloud.key"
DEBUG = True


def login():
    if os.path.isfile(SESSION_FILE):
        with open(SESSION_FILE) as K:
            pyncm.SetCurrentSession(LoadSessionFromString(K.read()))
            print("读取登录信息成功:[ %s ]" % pyncm.GetCurrentSession().login_info['content']['profile']['nickname'])
            return
    else:
        print("未能成功读取登录信息\n请选择登陆方式:\n[1]手机号+密码登录  [2]手机号+验证码登录  [3]二维码登录")
        WAY = int(input())
        if WAY == 1:
            if DEBUG:
                PHONE = input('手机 >>>')
                PASSWD = input('密码 >>>')
            else:
                PASSWD = getpass.getpass('密码 >>>')
            pyncm.login.LoginViaCellphone(PHONE, PASSWD)
            WriteLoginInfo(GetCurrentLoginStatus())
        elif WAY == 2:
            PHONE = input("手机 >>>")
            if pyncm.login.CheckIsCellphoneRegistered(PHONE)['exist'] != 1:
                print("手机号未注册,是否注册?")
                YN = input("Y/n >>>")
                if YN in ['y', 'Y']:
                    pyncm.login.SetSendRegisterVerifcationCodeViaCellphone(PHONE)
                    print("验证码发送成功\请依次输入验证码,昵称,密码.\n以空格分割")
                    VERIFY, NICKNAME, PASSWORD = input(">>>").split(" ")
                    pyncm.login.SetRegisterAccountViaCellphone(PHONE, VERIFY, NICKNAME, PASSWORD)
                elif YN in ['n', 'N']:
                    exit()
            elif pyncm.login.SetSendRegisterVerifcationCodeViaCellphone(PHONE)['data']:
                print("验证码发送成功!")
                VERIFY_CODE = input("验证码 >>>")
                if pyncm.login.GetRegisterVerifcationStatusViaCellphone(PHONE, VERIFY_CODE)['data']:
                    print("该手机号已注册" + pyncm.login.CheckIsCellphoneRegistered(PHONE)['nickname'])
                    print("如果这是您要登录的账号,请输入密码")
                    if DEBUG:
                        PASSWORD = input("密码 >>>")
                    else:
                        PASSWORD = getpass.getpass('密码 >>>')
                    pyncm.login.LoginViaCellphone(PHONE, PASSWORD)
                    WriteLoginInfo(GetCurrentLoginStatus())
            else:
                print("发送失败!可能是当时发送数量达到上限!")
                exit()
        elif WAY == 3:
            def dot_thingy():
                while True:
                    s = list('   ')
                    while s.count('.') < len(s):
                        s[s.count('.')] = '.'
                        yield ''.join(s)

            dot = dot_thingy()
            uuid = pyncm.login.LoginQrcodeUnikey()['unikey']
            url = f'https://music.163.com/login?codekey={uuid}'
            IMG = qrcode.make(url)
            IMG.show()
            print('[-] UUID:', uuid)
            while True:
                rsp = pyncm.login.LoginQrcodeCheck(uuid)
                if rsp['code'] == 803 or rsp['code'] == 800: break
                message = f"[!] {rsp['code']} -- {rsp['message']}"
                print(message, next(dot), end='\r')
                time.sleep(1)
            WriteLoginInfo(GetCurrentLoginStatus())
        else:
            exit()
    if pyncm.login.GetCurrentLoginStatus()['code'] == 200:
        with open(SESSION_FILE, 'w+') as K:
            K.write(pyncm.DumpSessionAsString(GetCurrentSession()))
        print('成功登录并保存了登录信息:', pyncm.GetCurrentSession().login_info['content']['profile']['nickname'], '已登录')
    return


def md5sum(file):
    md5sum = hashlib.md5()
    with open(file, 'rb') as f:
        while chunk := f.read():
            md5sum.update(chunk)
    return md5sum


def unlock(file):
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    unpad = lambda s: s[0:-(s[-1] if type(s[-1]) == int else ord(s[-1]))]
    f = open(file, 'rb')
    header = f.read(8)
    assert binascii.b2a_hex(header) == b'4354454e4644414d'
    f.seek(2, 1)
    key_length = f.read(4)
    key_length = struct.unpack('<I', bytes(key_length))[0]
    key_data = f.read(key_length)
    key_data_array = bytearray(key_data)
    for i in range(0, len(key_data_array)):
        key_data_array[i] ^= 0x64
    key_data = bytes(key_data_array)
    cryptor = AES.new(core_key, AES.MODE_ECB)
    key_data = unpad(cryptor.decrypt(key_data))[17:]
    key_length = len(key_data)
    key_data = bytearray(key_data)
    key_box = bytearray(range(256))
    c = 0
    last_byte = 0
    key_offset = 0
    for i in range(256):
        swap = key_box[i]
        c = (swap + last_byte + key_data[key_offset]) & 0xff
        key_offset += 1
        if key_offset >= key_length:
            key_offset = 0
        key_box[i] = key_box[c]
        key_box[c] = swap
        last_byte = c
    meta_length = f.read(4)
    meta_length = struct.unpack('<I', bytes(meta_length))[0]
    meta_data = f.read(meta_length)
    meta_data_array = bytearray(meta_data)
    for i in range(0, len(meta_data_array)):
        meta_data_array[i] ^= 0x63
    meta_data = bytes(meta_data_array)
    meta_data = base64.b64decode(meta_data[22:])
    cryptor = AES.new(meta_key, AES.MODE_ECB)
    meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
    meta_data = json.loads(meta_data)
    crc32 = f.read(4)
    crc32 = struct.unpack('<I', bytes(crc32))[0]
    f.seek(5, 1)
    image_size = f.read(4)
    image_size = struct.unpack('<I', bytes(image_size))[0]
    image_data = f.read(image_size)
    file_name = f.name.split("/")[-1].split(".ncm")[0] + '.' + meta_data['format']
    m = open(os.path.join(os.path.split(file)[0], file_name), 'wb')
    chunk = bytearray()
    while True:
        chunk = bytearray(f.read(0x8000))
        chunk_length = len(chunk)
        if not chunk:
            break
        for i in range(1, chunk_length + 1):
            j = i & 0xff
            chunk[i - 1] ^= key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
        m.write(chunk)
    m.close()
    f.close()
    return file_name


def ADD(NAME, LIST):
    TYPE = NAME.split('.')[-1]
    if TYPE == 'ncm':
        LIST.append(unlock(NAME))
        print(" ")
    elif TYPE in ['MP3', 'mp3', 'flac', 'FLAC']:
        LIST.append(NAME)


def upload(f):
    fname = os.path.basename(f)
    fext = f.split('.')[-1]
    fsize = os.stat(f).st_size
    md5 = md5sum(f).hexdigest()
    try:
        INFO = tinytag.TinyTag.get(f)
    except:
        print("文件有误!无法读取信息!")
        input()
        exit()
    cresult = pyncm.cloud.GetCheckCloudUpload(md5)
    songId = cresult['songId']
    token = pyncm.cloud.GetNosToken(fname, md5, str(fsize), fext)['result']
    if cresult['needUpload']:
        pyncm.cloud.SetUploadObject(open(f, 'rb'), md5, fsize, token['objectKey'], token['token'])
    try:
        submit_result = pyncm.cloud.SetUploadCloudInfo(token['resourceId'], songId, md5, fname, INFO.title, INFO.artist,
                                                       INFO.album, INFO.bitrate)
        publish_result = pyncm.cloud.SetPublishCloudResource(submit_result['songId'])
    except KeyError:
        submit_result = pyncm.cloud.SetUploadCloudInfo(token['resourceId'], songId, md5, fname)
        publish_result = pyncm.cloud.SetPublishCloudResource(submit_result['songId'])


if __name__ == "__main__":
    try:
        login()
    except:
        print("登陆失败!\n按回车键退出")
        input()
        exit()
    FINAL_LIST = []
    try:
        GOOD = sys.argv[1]
        FULL = sys.argv[1:]
    except IndexError:
        print("请输入欲上传的文件或目录")
        FULL = [input(">>>")]

    for i in FULL:
        if os.path.isdir(i):
            LIST = os.listdir(i)
            for j in range(0, len(LIST)):
                ADD(os.path.join(i, LIST[j]), FINAL_LIST)
        else:
            ADD(i, FINAL_LIST)
    TMP = set(FINAL_LIST)
    FINAL_LIST = list(TMP)
    JJ = 0
    for i in FINAL_LIST:
        try:
            upload(i)
            JJ = JJ + 1
            print(f"{i}上传完成!")
        except KeyError:
            print(f"\n{i}上传失败!可能是上传过于频繁")
            print("请尝试再次上传")
    input(f"完成!共上传{JJ}首歌曲!\n按回车键退出...")
    exit()
