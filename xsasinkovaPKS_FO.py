import ast
import base64
import json
import math
import random
import socket
import struct
import threading
import sys
import time
import crcmod
from linecache import cache
from pickle import GLOBAL
from pathlib import Path
import queue

RED = "\033[31m"
GREEN = "\033[32m"
BLUE = "\033[34m"
ZLTA = "\033[33m"
ORANZOVA = "\033[38;5;214m"
RUZOVA = "\033[35m"
AZUROVA = "\033[36m"
SIVA = "\033[37m"
# reset na defaultnu farbu
RESET = "\033[0m"

CIELOVY_ADRESA_PRE_ULOZENIE_SUBORU = "c:/Homework/#file-ciel"

SYSTEM_EXIT_TIMEOUT = 10

zapiname_keep_alive = 0
sync = None
syn_num = 0
fin_num = None
hodnota_init_syn = None
max_seq_num = None
data_queue = queue.Queue()
ret_queue = queue.Queue()
keep_alive_queue = queue.Queue()
keep_alive_exit_queue = queue.Queue()
zbehla_prva = None
nazov_suboru = None
kontrola = [None]
issue_sn = []
random_issue_sn = []

# na kazdu spravu mam specificku hlavicku
type_of_msg_syn = b's'  # SYN sprava, b - v bajtoch, typ spravy - 1B
type_of_msg_3w = b'w'  # 3w sprava
type_of_msg_ack = b'a'  # ACK sprava
type_of_msg_data_con = b'x'  # DATA sprava - do konzoly (textova sprava)
type_of_msg_data_file = b'y'  # DATA sprava - file
type_of_msg_ret = b'r'  # RET sprava
type_of_msg_fin = b'f'  # FIN sprava
type_of_msg_3f = b'k'  # 3F sprava
type_of_msg_fin_ack = b'q'  # FIN-ACK sprava
type_of_msg_data_file_prva = b'p'  # prva sprava - file
type_of_msg_prva = b't'  # prva sprava - konzola
type_of_msg_keep = b'e'  # KEEP-ALIVE sprava
type_of_msg_keep_ack = b'o'  # ACK sprava pre KEEP ALIVE

keep_alive_msg_array = []
keep_alive_last_activity_time = time.time()
keep_alive_seq_num = 0
keep_alive_ack_received = False

mtu_value = 1451
ciel_start_time_celkovy_cas_trvania_prenosu = time.time()


def encap_3w_msg(num):
    syn_num = random.randint(1, 100)
    header = struct.pack('!c H H', type_of_msg_3w, syn_num, num + 1)  # num + 1 je moje acknow. cislo
    return header, syn_num


def decap_3w_msg(data):
    header_size = struct.calcsize('!c H H')
    print("VELKOST 3W HEADRA JE:" + str(header_size))
    unpacked_header = struct.unpack('!c H H', data)
    type_of_msg_syn, syn_num, ack_num = unpacked_header
    return syn_num, ack_num


def encap_ack(num):
    num = num + 1
    header = struct.pack('!c H', type_of_msg_ack, num)
    return header


def decap_ack(data):
    header_size = struct.calcsize('!c H')
    print("VELKOST ACK HEADRA JE:" + str(header_size))
    unpacked_header = struct.unpack('!c H', data)
    type_of_msg_syn, ack_num = unpacked_header
    return ack_num


# prijmem celu spravu - data, data = payload + hlavic.
def decap_data_msg(data):
    header_size = struct.calcsize('!c I H')
    print("VELKOST DATA HEADRA JE:" + str(header_size))
    header = data[:7]
    unpacked_header = struct.unpack('!c I H', header)
    a, sn, fcs = unpacked_header
    payload = data[7:mtu_value].decode()
    return sn, fcs, payload


def encap_ret_msg(issue_sn):
    header = struct.pack('!c', type_of_msg_ret)
    odosli = header + str(issue_sn).encode()
    return odosli


def decap_ret_msg(data):
    header = data[:1]
    unpacked_header = struct.unpack('!c', header)
    a = unpacked_header
    payload = data[1:1500].decode()
    return payload


def encap_syn_msg():
    syn_num = random.randint(1, 100)
    header = struct.pack('!c H', type_of_msg_syn, syn_num)
    return header, syn_num


def decap_syn_msg(header_data):
    header_size = struct.calcsize('!c H')
    print("VELKOST SYN HEADRA JE:" + str(header_size))
    unpacked_header = struct.unpack('!c H', header_data)
    type_of_msg_syn, num = unpacked_header
    print("SYN NUM: " + str(num))
    return num


def encap_prva_data_sprava_msg(socket, ip, port, mtu, max_seqauence_nmber):
    header = struct.pack('!c I', type_of_msg_prva, max_seqauence_nmber)
    socket.sendto(header, (ip, port))
    nastala_komunikacia_keep_a_live()


def decap_prva_data_sprava_msg(data):
    header_size = struct.calcsize('!c I')
    print("VELKOST DATA HEADRA JE:" + str(header_size))
    header = data[:5]
    unpacked_header = struct.unpack('!c I', header)
    payload = data[5:mtu_value].decode()
    a, max_seqauence_nmber = unpacked_header
    return max_seqauence_nmber


def encap_prva_data_sprava_file(socket, ip, port, mtu, max_seqauence_nmber, payload):
    header = struct.pack('!c I', type_of_msg_data_file_prva, max_seqauence_nmber)
    odosli = header + str(payload).encode()
    socket.sendto(odosli, (ip, port))  #
    nastala_komunikacia_keep_a_live()


def decap_prva_data_sprava_file(data):
    global nazov_suboru
    header_size = struct.calcsize('!c I')
    print("VELKOST DATA HEADRA JE:" + str(header_size))
    header = data[:5]
    unpacked_header = struct.unpack('!c I', header)
    payload = data[5:mtu_value].decode(errors="ignore")
    nazov_suboru = payload
    a, max_seqauence_nmber = unpacked_header
    return max_seqauence_nmber


def msg_create_ERROR_CRC_checksum_fragmentu(sn, payload):
    # vytvorenie objektu CRC s pouzitim crc-16 algoritmu
    crc16 = crcmod.predefined.Crc('crc-16')
    # umele vytvorenie chyby v CRC
    crc16.update(str("FCS ERROR").encode())
    # ziskanie finalnej hodnoty CRC16 checksumu
    error_crc_checksum = crc16.hexdigest()
    print(
        f"{RED}Vytvoreny checksum pre fragment {sn} - poskodeny{RESET}, SN: {sn}, CRC16 checksum: {error_crc_checksum}, data: {payload}")
    return error_crc_checksum


def msg_create_CRC_checksum_fragmentu(sn, payload):
    # vytvorenie objektu CRC s pouzitim crc-16 algoritmu
    crc16 = crcmod.predefined.Crc('crc-16')
    # ziskanie obsahu fragmentu z payload
    data = payload.encode()
    # aktualizacia CRC s datami fragmentu
    crc16.update(data)
    # ziskanie finalnej hodnoty CRC16 checksumu
    crc_checksum = crc16.hexdigest()
    print(
        f"{GREEN}Vytvoreny checksum pre fragment {sn}{RESET}, SN: {sn}, CRC16 checksum: {crc_checksum}, data: {payload}")
    return crc_checksum


# rozdelenie spravy na viac fragmentpv
def split_message(message, payload_size):
    return [message[i:i + payload_size] for i in range(0, len(message), payload_size)]


def encap_data_msg(flag, socket, ip, port, str, mtu, max_seq_num):
    # mtu = maximalna velkost fragmentu (bez headrov), ktoru posielam, tz maximalny pocet bajtov, kt. viem poslat v jednom fragmente
    payload_size = mtu
    # vytvorim cache, do ktorych si budem vkladat obsah fragmentov
    klient_cache = {}
    # rozdelim pozadovanu spravu zo vstupu do fragmentov, posledny fragment moze byt kratsi
    payloads = split_message(str, payload_size)

    # parameter, ktory inkrementujem, aby som vedela, ktory fragment v poradi posielam
    msg_poradove_cislo_posielaneho_fragmentu = 0
    # parameter, ktory inkremtujem, aby som vedela, ktory fragment v %5 poradi posielam (mozu byt len cisla: od 1 do 5)
    msg_priebezne_poradove_cislo_posielaneho_fragmentu = 0
    # parameter, pocet fragmentov, ktory nebol uspesne prijaty v danom cykle (cyklus je %5)
    msg_pocet_fragmentov_pre_opatovne_odoslanie = 0

    for payload in payloads:

        print(
            f"{RUZOVA}Odosielany fragment {msg_poradove_cislo_posielaneho_fragmentu}, velkost fragmentu: {len(payload)}{RESET}")

        # vytvorenie CRC hodnoty, ktora sluzi na vypocitanie kontrolneho suctu iba z payload
        # na zaklade vstupnej hodnoty vytvorenie poctu umelo vytvorenych chyb, bolo vytvorene pole s identifikaciou, ktory fragment bude pokazeny
        # ak som vo fragmente, ktory ma nastavene, ze ma byt pokazeny, idem ho pokazit
        if random_issue_sn[msg_poradove_cislo_posielaneho_fragmentu + 1] == 1:
            crc_checksum = msg_create_ERROR_CRC_checksum_fragmentu(msg_poradove_cislo_posielaneho_fragmentu, payload)
        else:
            crc_checksum = msg_create_CRC_checksum_fragmentu(msg_poradove_cislo_posielaneho_fragmentu, payload)

        # vlozenie obsahu fragmentu do cache
        klient_cache[msg_poradove_cislo_posielaneho_fragmentu] = payload

        # vytvorenie datovej hlavicky
        header = struct.pack('!c I H', flag, msg_poradove_cislo_posielaneho_fragmentu, int(crc_checksum, 16))

        # k vytvorenej datovej hlavicke pripojim obsah fragmentu v podobe payloadu
        odosli = header + payload.encode()
        socket.sendto(odosli, (ip, port))
        nastala_komunikacia_keep_a_live()

        # po odoslani fragmentu navysujem poradove cislo pre odoslanie dalsieho fragmentu
        msg_poradove_cislo_posielaneho_fragmentu = msg_poradove_cislo_posielaneho_fragmentu + 1
        msg_priebezne_poradove_cislo_posielaneho_fragmentu = msg_priebezne_poradove_cislo_posielaneho_fragmentu + 1

        # dochadza k odosielaniu 5teho fragmentu v poradi ?
        if (msg_priebezne_poradove_cislo_posielaneho_fragmentu + msg_pocet_fragmentov_pre_opatovne_odoslanie) % 5 == 0:
            msg_pocet_fragmentov_pre_opatovne_odoslanie = msg_posielanie_fragmentu_keep_alive(max_seq_num, klient_cache,
                                                                                              msg_priebezne_poradove_cislo_posielaneho_fragmentu,
                                                                                              flag, socket, ip, port)
            msg_priebezne_poradove_cislo_posielaneho_fragmentu = 0

        # dochadza k odosielaniu posledneho fragmentu v poradi ?
        if max_seq_num == msg_poradove_cislo_posielaneho_fragmentu:
            msg_pocet_fragmentov_pre_opatovne_odoslanie = msg_posielanie_fragmentu_keep_alive(max_seq_num, klient_cache,
                                                                                              msg_priebezne_poradove_cislo_posielaneho_fragmentu,
                                                                                              flag, socket, ip, port)
            msg_priebezne_poradove_cislo_posielaneho_fragmentu = 0


def msg_posielanie_fragmentu_keep_alive(max_seq_num, klient_cache, msg_pocet_fragmentov_pre_odoslanie, flag, socket, ip,
                                        port):
    global sns
    # doba cakania na RET spravu, po uplynuti tejto doby zacnem posielat keep alive
    MAX_CAS_CAKANIA_NA_RET_MSG = 5

    # flag, ktory oznacuje, ci prebieha alebo neprebieha keep-alive
    prebieha_keep_alive = 0

    # cas zaciatku posielania fragmentu
    start_time = time.time()

    while True:
        # cas, ktorym sledujem trvanie odosielania fragmentu od jeho zaciatku
        priebezny_time = time.time()

        # ak od priebezneho casu odpocitam zaciatocny cas, dostanem dobu cakania na RET spravu, ak tato doba
        # je do 5 sekund, tak cakam na RET spravu, inak zacinam posielat KEEP-ALIVE spravy
        if priebezny_time - start_time < MAX_CAS_CAKANIA_NA_RET_MSG:

            # ak v queue nemam k dispozicii ziadnu RET spravu, cakam, v opacnom pripade RET spravu spracujem
            if not ret_queue.empty():
                ret_data_vybrate = ret_queue.get()
                print(
                    f"{ZLTA}Prijatie RET {RESET} spravy z QUEUE - QSIZE: {ret_queue.qsize()}, hodnota: {str(ret_data_vybrate)}")
                # ziskavam informacie z RET spravy (sn neuspesne prijatych fragmentov)
                sns = decap_ret_msg(ret_data_vybrate)

                # ak sa v RET sprave nachadzaju sn cisla nespravne prijatych fragmentov, tak ich opatovne odoslem
                return msg_posielanie_fragmentu(sns, max_seq_num, klient_cache, flag, socket, ip, port)

        else:
            # ak KEEP-ALIVE nebezi a neobdrazala som RET spravu do 5 sekund, tak vlozim do queue pre KEEP-ALIVE informaciu,
            # ze posielanie fragmentov bolo prerusene a pozadujem, aby thread KEEP-ALIVE posielal KEEP-ALIVE spravy
            # v pozadovanych intervaloch, kym sa spojenie neobnovi
            if prebieha_keep_alive == 0:
                print(f"{ORANZOVA}Nedostali sme RET spravu - spojenie keep a live{RESET}")
                while not keep_alive_queue.empty():
                    keep_alive_queue.get()
                keep_alive_queue.put(["KEEP_ALIVE_POSIELANIE_MSG_PRERUSENE"])

                # nastavenie priznaku, ze KEEP-ALIVE zacal prebiehat
                prebieha_keep_alive = 1

            else:
                # ak sa v queue pre KEEP-ALIVE nachadza hodnota, thread KEEP-ALIVE ma informoval o opatovnom obnoveni spojenia
                if not keep_alive_queue.empty():
                    # citam z queue message pre KEEP-ALIVE a zistujem, aka message z tohto vlakna prisla
                    keep_alive_hodnota = keep_alive_queue.get()
                    typSpravyQueueKeepAlive = keep_alive_hodnota[0]
                    print(typSpravyQueueKeepAlive)

                    # ak typ spravy, ktory prisiel z queue je obnovenie, tak sa pokusim opatovne odoslat
                    # posledne odoslane fragmenty od momentu, kedy doslo k odpojeniu (odkedy som nedostala RET spravu
                    # o posledne prijatom spravnom fragmente)
                    if typSpravyQueueKeepAlive == "KEEP_ALIVE_POSIELANIE_MSG_OBNOVENE":
                        print(f"{ORANZOVA}Posielanie spravy bolo obnovene - spojenie bolo obnovene{RESET}")

                        # vytvorenie pola fragmentov, ktore neboli odoslane, resp. prijate druhou stranou pri nedostupnosti ciela (ked bezalo keep a live)

                        # prevedenie pola na string, ktory bude vstupom do metody, ktora sa vyuziva na opatovne
                        # odoslanie fragmentov na stranu cieloveho uzla, vyuzitie tejto metody sa pouziva pri opakovanom
                        # posielani chybnych fragementov

                        # zistenie pozicie v poli prijatych fragmentov, ku ktorej bola naposledy poslana RET sprava
                        msg_pocet_fragmentov_pre_odoslanie_od = len(klient_cache) - msg_pocet_fragmentov_pre_odoslanie

                        # pole, do ktoreho budem plnit snka fragmentov, ktore pozadujem znova odoslat
                        # v poli bude na prvej pozicii znak "[", na dalsich poziciach budu snka oddelene ciarkou a na poslednej znak "]"
                        # priklad ako string: [1, 2, 3]
                        klient_cache_keep_a_live = []

                        # poradove cislo odoslaneho fragmentu
                        index = 0
                        klient_cache_keep_a_live.append("[")

                        # prechadzanie vsetkych doposial odoslanych fragmentov
                        # v hodnote budem mat snko
                        for hodnota in klient_cache:

                            # ak index (porad. c. odoslaneho fragmentu) je >= ako cislo, posledne spravne odoslaneho fragmentu,
                            # zacnem snka tychto fragmentov davat do pola pre opatovne odoslanie
                            if index >= msg_pocet_fragmentov_pre_odoslanie_od:
                                klient_cache_keep_a_live.append(str(hodnota))

                                # davam ciarky do pola dovtedy, kym nevkladam posledne snko
                                if index < (len(klient_cache) - 1):
                                    klient_cache_keep_a_live.append(", ")
                            index = index + 1
                        klient_cache_keep_a_live.append("]")

                        # spravenie stringu z pola
                        klient_cache_keep_a_live_result = ''.join(klient_cache_keep_a_live)

                        # zavolanie tejto metody sposobi opatovne odoslanie fragmentov, ktore neboli odoslane,
                        # napr. z dovodu odpojenia kabla
                        return msg_posielanie_fragmentu(klient_cache_keep_a_live_result, max_seq_num, klient_cache,
                                                        flag, socket, ip, port)

# opatovne odosielanie fragmentov
def msg_posielanie_fragmentu(sns, max_seq_num, klient_cache, flag, socket, ip, port):
    global keep_alive_msg_array

    # pretransformovanie si chybne prijatych fragmentov, ktore prisli v sprave do pola
    pocet_fragmentov_pre_odoslanie = ast.literal_eval(sns)
    print(f"Pocet fragmentov pre odoslanie: {len(pocet_fragmentov_pre_odoslanie)} z celkoveho poctu {max_seq_num}")

    # ak nevznikli chyby pocas posielania, idem posielat dalsiu skupinu fragmentov (piatich)
    if len(pocet_fragmentov_pre_odoslanie) == 0:
        print("Nezvnikli chyby, neposielame ziadny opravny fragment")
        # neboli identifikovane ziadne prijate fragmenty
        return 0

    # ak vznikli chyby pocas posielania, posielam znova fragmenty
    else:
        print("Posielame opatovne chybne alebo stratene fragmety")

        # prechadzanie vsetkych chybne prjatych fragmentov, ktore mi prisli v RET sprave a opatovne ich odosielam -
        # v sprave mi prisli sn cisla fragmentov
        for poradove_cislo_nedoruceneho_fragmentu in pocet_fragmentov_pre_odoslanie:

            # ziskanie fragmentu z pola fragmentov, ktore boli odoslane na zaklade sn cisla zo spravy
            payload = klient_cache[poradove_cislo_nedoruceneho_fragmentu]

            # vypocitanie crc pre fragment (aby som crc poslala spravny)
            crc_hodnota_chybneho_fragmentu = int(
                msg_create_CRC_checksum_fragmentu(poradove_cislo_nedoruceneho_fragmentu, payload), 16)
            print(
                f"{GREEN}Posielame chybny alebo strateny fragment: {poradove_cislo_nedoruceneho_fragmentu}{RESET}, CRC: {crc_hodnota_chybneho_fragmentu}")

            # vytvorenie datovej hlavicky
            header = struct.pack('!c I H', flag, poradove_cislo_nedoruceneho_fragmentu, crc_hodnota_chybneho_fragmentu)
            odosli = header + payload.encode()
            socket.sendto(odosli, (ip, port))
            nastala_komunikacia_keep_a_live()

        # pocet opatovne odoslanych fragmentov
        return len(pocet_fragmentov_pre_odoslanie)


def file_create_ERROR_CRC_checksum_fragmentu(sn, payload):
    # vytvorenie objektu CRC s pouzitim crc-16 algoritmu
    crc16 = crcmod.predefined.Crc('crc-16')
    # umele vytvorenie chyby v CRC
    crc16.update(str("FCS ERROR").encode())
    # ziskanie finalnej hodnoty CRC16 checksumu
    error_crc_checksum = crc16.hexdigest()
    print(
        f"{RED}Vytvoreny checksum pre fragment {sn} - poskodeny{RESET}, SN: {sn}, CRC16 checksum: {error_crc_checksum}")
    return error_crc_checksum


def file_create_CRC_checksum_fragmentu(sn, payload):
    # vytvorenie objektu CRC s pouzitim crc-16 algoritmu
    crc16 = crcmod.predefined.Crc('crc-16')
    # ziskanie obsahu fragmentu z payload
    data = payload.encode()
    # aktualizacia CRC s datami fragmentu
    crc16.update(data)
    # ziskanie finalnej hodnoty CRC16 checksumu
    crc_checksum = crc16.hexdigest()
    print(f"{GREEN}Vytvoreny checksum pre fragment {sn}{RESET}, SN: {sn}, CRC16 checksum: {crc_checksum}")
    return crc_checksum


def encap_data_file(flag, socket, ip, port, str, mtu):
    # mtu = maximalna velkost fragmentu (bez headrov), ktoru posielam, tz maximalny pocet bajtov, kt. viem poslat v jednom fragmente
    payload_size = mtu
    # vytvorim cache, do ktorych si budem vkladat obsah fragmentov
    klient_cache = {}
    # rozdelim pozadovanu spravu zo vstupu do fragmentov, posledny fragment moze byt kratsi
    payloads = split_message(str, payload_size)

    # parameter, ktory inkrementujem, aby som vedela, ktory fragment v poradi posielam
    file_poradove_cislo_posielaneho_fragmentu = 0
    # parameter, ktory inkrementujem, aby som vedela, ktory fragment v %5 poradi posielam (mozu byt len cisla: od 1 do 5)
    file_priebezne_poradove_cislo_posielaneho_fragmentu = 0
    # parameter, pocet fragmentov, ktory nebol uspesne prijaty v danom cykle (cyklus je %5)
    file_pocet_fragmentov_pre_opatovne_odoslanie = 0

    for payload in payloads:

        print(
            f"{RUZOVA}Odosielany fragment {file_poradove_cislo_posielaneho_fragmentu}, velkost fragmentu: {len(payload)}{RESET}")

        # vytvorenie CRC hodnoty, ktora sluzi na vypocitanie kontrolneho suctu iba z payload
        # na zaklade vstupnej hodnoty vytvorenie poctu umelo vytvorenych chyb, bolo vytvorene pole s identifikaciou, ktory fragment bude pokazeny
        # ak som vo fragmente, ktory ma nastavene, ze ma byt pokazeny, idem ho pokazit
        if random_issue_sn[file_poradove_cislo_posielaneho_fragmentu] == 1:
            crc_checksum = file_create_ERROR_CRC_checksum_fragmentu(file_poradove_cislo_posielaneho_fragmentu, payload)
        else:
            crc_checksum = file_create_CRC_checksum_fragmentu(file_poradove_cislo_posielaneho_fragmentu, payload)

        # vlozenie obsahu fragmentu do cache
        klient_cache[file_poradove_cislo_posielaneho_fragmentu] = payload

        # vytvorenie datovej hlavicky
        header = struct.pack('!c I H', flag, file_poradove_cislo_posielaneho_fragmentu, int(crc_checksum, 16))

        # k vytvorenej datovej hlavicky pripojim obsah fragmntu v podobe payloadu
        odosli = header + payload.encode()
        socket.sendto(odosli, (ip, port))
        nastala_komunikacia_keep_a_live()

        # po odoslani fragmentu navysujem poradove cislo pre odoslanie dalsieho fragmentu
        file_poradove_cislo_posielaneho_fragmentu = file_poradove_cislo_posielaneho_fragmentu + 1
        file_priebezne_poradove_cislo_posielaneho_fragmentu = file_priebezne_poradove_cislo_posielaneho_fragmentu + 1

        if (
                file_priebezne_poradove_cislo_posielaneho_fragmentu + file_pocet_fragmentov_pre_opatovne_odoslanie) % 5 == 0:
            file_pocet_fragmentov_pre_opatovne_odoslanie = file_posielanie_fragmentu_keep_alive(max_seq_num,
                                                                                                klient_cache,
                                                                                                file_priebezne_poradove_cislo_posielaneho_fragmentu,
                                                                                                flag, socket, ip, port)
            file_priebezne_poradove_cislo_posielaneho_fragmentu = 0

        # dochadza k odosielaniu posledneho fragmentu v poradi ?
        if max_seq_num == file_poradove_cislo_posielaneho_fragmentu:
            file_pocet_fragmentov_pre_opatovne_odoslanie = file_posielanie_fragmentu_keep_alive(max_seq_num,
                                                                                                klient_cache,
                                                                                                file_priebezne_poradove_cislo_posielaneho_fragmentu,
                                                                                                flag, socket, ip, port)
            file_priebezne_poradove_cislo_posielaneho_fragmentu = 0


# odosle sa 5 a caka sa na ret, ak pridu vsetky v poriadku, pusti sa dalsich 5 (prazdne pole)
# ak nepride prazdne pole, tak si PC2 vypyta tie s danymi id, ktore pridu

def file_posielanie_fragmentu_keep_alive(max_seq_num, klient_cache, file_pocet_fragmentov_pre_odoslanie, flag, socket,
                                         ip, port):
    global sns

    # doba cakania na RET spravu, po uplynuti tejto doby zacnem posielat keep alive
    MAX_CAS_CAKANIA_NA_RET_MSG = 5

    # flag, ktory oznacuje, ci prebieha alebo neprebieha keep-alive
    prebieha_keep_alive = 0

    # cas zaciatku posielania fragmentu
    start_time = time.time()

    while True:
        # cas, ktorym sledujem trvanie odosielania fragmentu od jeho zaciatku
        priebezny_time = time.time()

        # ak od priebezneho casu odpocitam zaciatocny cas, dostanem dobu cakania na RET spravu, ak tato doba
        # je do 5 sekund, tak cakam na RET spravu, inak zacinam posielat KEEP-ALIVE spravy
        if priebezny_time - start_time < MAX_CAS_CAKANIA_NA_RET_MSG:

            # ak v queue nemam k dispozicii ziadnu RET spravu, cakam, v opacnom pripade RET spravu spracujem
            if not ret_queue.empty():
                ret_data_vybrate = ret_queue.get()
                print(
                    f"{ZLTA}Prijatie RET {RESET} spravy z QUEUE - QSIZE: {ret_queue.qsize()}, hodnota: {str(ret_data_vybrate)}")
                # ziskavam informacie z RET spravy (sn neuspesne prijatych fragmentov)
                sns = decap_ret_msg(ret_data_vybrate)

                # ak sa v RET sprave nachadzaju sn cisla nespravne prijatych fragmentov, tak ich opatovne odoslem
                return file_posielanie_fragmentu(sns, max_seq_num, klient_cache, flag, socket, ip, port)

        else:
            # ak KEEP-ALIVE nebezi a neobdrazala som RET spravu do 5 sekund, tak vlozim do queue pre KEEP-ALIVE informaciu,
            # ze posielanie fragmentov bolo prerusene a pozadujem, aby thread KEEP-ALIVE posielal KEEP-ALIVE spravy
            # v pozadovanych intervaloch, kym sa spojenie neobnovi
            if prebieha_keep_alive == 0:
                print(f"{ORANZOVA}Nedostali sme RET spravu - spojenie keep a live{RESET}")
                while not keep_alive_queue.empty():
                    keep_alive_queue.get()
                keep_alive_queue.put(["KEEP_ALIVE_POSIELANIE_MSG_PRERUSENE"])

                # nastavenie priznaku, ze KEEP-ALIVE zacal prebiehat
                prebieha_keep_alive = 1

            else:
                # ak sa v queue pre KEEP-ALIVE nachadza hodnota, thread KEEP-ALIVE ma informoval o opatovnom obnoveni spojenia
                if not keep_alive_queue.empty():
                    # citam z queue message pre KEEP-ALIVE a zistujem, aka message z tohto vlakna prisla
                    keep_alive_hodnota = keep_alive_queue.get()
                    typSpravyQueueKeepAlive = keep_alive_hodnota[0]
                    print(typSpravyQueueKeepAlive)

                    # ak typ spravy, ktory prisiel z queue je obnovenie, tak sa pokusim opatovne odoslat
                    # posledne odoslane fragmenty od momentu, kedy doslo k odpojeniu (odkedy som nedostala RET spravu
                    # o posledne prijatom spravnom fragmente)
                    if typSpravyQueueKeepAlive == "KEEP_ALIVE_POSIELANIE_MSG_OBNOVENE":
                        print(f"{ORANZOVA}Posielanie spravy bolo obnovene - spojenie bolo obnovene{RESET}")

                        # prevedenie pola na string, ktory bude vstupom do metody, ktora sa vyuziva na opatovne
                        # odoslanie fragmentov na stranu cieloveho uzla, vyuzitie tejto metody sa pouziva pri opakovanom
                        # posielani chybnych fragementov

                        # zistenie pozicie v poli prijatych fragmentov, ku ktorej bola naposledy poslana RET sprava
                        file_pocet_fragmentov_pre_odoslanie_od = len(klient_cache) - file_pocet_fragmentov_pre_odoslanie

                        # pole, do ktoreho budem plnit snka fragmentov, ktore pozadujem znova odoslat
                        # v poli bude na prvej pozicii znak "[", na dalsich poziciach budu snka oddelene ciarkou a na poslednej znak "]"
                        # priklad ako string: [1, 2, 3]
                        klient_cache_keep_a_live = []

                        # poradove cislo odoslaneho fragmentu
                        index = 0

                        klient_cache_keep_a_live.append("[")

                        # prechadzanie vsetkych doposial odoslanych fragmentov
                        # v hodnote budem mat snko
                        for hodnota in klient_cache:

                            # ak index (porad. c. odoslaneho fragmentu) je >= ako cislo, posledne spravne odoslaneho fragmentu,
                            # zacnem snka tychto fragmentov davat do pola pre opatovne odoslanie
                            if index >= file_pocet_fragmentov_pre_odoslanie_od:
                                klient_cache_keep_a_live.append(str(hodnota))
                                # davam ciarky do pola dovtedy, kym nevkladam posledne snko
                                if index < (len(klient_cache) - 1):
                                    klient_cache_keep_a_live.append(", ")
                            index = index + 1
                        klient_cache_keep_a_live.append("]")
                        # spravenie stringu z pola
                        klient_cache_keep_a_live_result = ''.join(klient_cache_keep_a_live)

                        # zavolanie tejto metody sposobi opatovne odoslanie fragmentov, ktore neboli odoslane,
                        # napr. z dovodu odpojenia kabla
                        return file_posielanie_fragmentu(klient_cache_keep_a_live_result, max_seq_num, klient_cache,
                                                         flag, socket, ip, port)

# opatovne odosielanie fragmentov
def file_posielanie_fragmentu(sns, max_seq_num, klient_cache, flag, socket, ip, port):
    global keep_alive_msg_array

    # pretransformovanie si chybne prijatych fragmentov, ktore prisli v subore do pola
    pocet_fragmentov_pre_odoslanie = ast.literal_eval(sns)
    print(f"Pocet fragmentov pre odoslanie: {len(pocet_fragmentov_pre_odoslanie)} z celkoveho poctu {max_seq_num}")

    # ak nevznikli chyby pocas posielania, idem posielat dalsiu skupinu fragmentov (piatich)
    if len(pocet_fragmentov_pre_odoslanie) == 0:
        print("Nezvnikli chyby, neposielam ziadny opravny fragment")
        # neboli identifikovane ziadne prijate fragmenty
        return 0

    # ak vznikli chyby pocas posielania, posielam znova fragmenty
    else:
        print("Posielame opatovne chybne alebo stratene fragmety")

        # prechadzanie vsetkych chybne prijatych fragmentov, ktore mi prisli v RET sprave a opatovne ich odosielam -
        # v sprave mi prisli sn cisla fragmentov
        for poradove_cislo_nedoruceneho_fragmentu in pocet_fragmentov_pre_odoslanie:

            # ziskanie fragmentu z pola fragmentov, ktore boli odoslane na zaklade sn cisla zo suboru
            payload = klient_cache[poradove_cislo_nedoruceneho_fragmentu]

            # vypocitanie crc pre fragment (aby som crc poslala spravny)
            crc_hodnota_chybneho_fragmentu = int(
                file_create_CRC_checksum_fragmentu(poradove_cislo_nedoruceneho_fragmentu, payload), 16)
            print(
                f"{GREEN}Posielame chybny alebo strateny fragment: {poradove_cislo_nedoruceneho_fragmentu}{RESET}, CRC: {crc_hodnota_chybneho_fragmentu}")

            # vytvorenie datovej hlavicky
            header = struct.pack('!c I H', flag, poradove_cislo_nedoruceneho_fragmentu, crc_hodnota_chybneho_fragmentu)
            odosli = header + payload.encode()
            socket.sendto(odosli, (ip, port))
            nastala_komunikacia_keep_a_live()

        # pocet opatovne odoslanych fragmentov
        return len(pocet_fragmentov_pre_odoslanie)


###################################################################################################################
def encap_fin_msg():
    fin_num = random.randint(1, 100)
    header = struct.pack('!c H', type_of_msg_fin, fin_num)
    return fin_num, header


def decap_fin_msg(header_data):
    header_size = struct.calcsize('!c H')
    print("VELKOST FIN HEADRA JE:" + str(header_size))
    unpacked_header = struct.unpack('!c H', header_data)
    type_of_msg_fin, num = unpacked_header
    print("FIN NUM: " + str(num))
    return num


def encap_3f_msg(num):
    fin_num = random.randint(1, 100)
    header = struct.pack('!c H H', type_of_msg_3f, fin_num, num + 1)
    return header, fin_num


def decap_3f_msg(data):
    header_size = struct.calcsize('!c H H')
    print("VELKOST 3F HEADRA JE:" + str(header_size))
    unpacked_header = struct.unpack('!c H H', data)
    type_of_msg_3f, fin_num, ack_num = unpacked_header
    return fin_num, ack_num


def encap_finack(fin):
    num = fin + 1
    header = struct.pack('!c H', type_of_msg_fin_ack, num)
    return header


def decap_finack(data):
    header_size = struct.calcsize('!c H')
    print("VELKOST FIN-ACK HEADRA JE:" + str(header_size))
    unpacked_header = struct.unpack('!c H', data)
    type_of_msg_syn_ack, ack_num = unpacked_header
    return ack_num


def kontrola_poctu(data):
    ret_queue.put(data)


def encap_keep_alive(keep_alive_seq_num):
    header = struct.pack('!c I', type_of_msg_keep, keep_alive_seq_num)
    return header, keep_alive_seq_num


def dencap_keep_alive(data):
    unpacked_header = struct.unpack('!c I', data)
    a, keep_alive_seq_num = unpacked_header
    return keep_alive_seq_num


def encap_keep_alive_ack(num):
    header = struct.pack('!c I', type_of_msg_keep_ack, num)
    return header


def dencap_keep_alive_ack(data):
    unpacked_header = struct.unpack('!c I', data)
    a, keep_num = unpacked_header
    return keep_num


def check_lost_fragment(msg_prijate_fragmenty_cache):
    index = 0
    stratene_fragmenty = []
    for fragment in msg_prijate_fragmenty_cache:
        if fragment == None:
            stratene_fragmenty.append(index)
        index = index + 1
    return stratene_fragmenty


def sent_ZdrojovyUzol(cielovy_uzol_socket, zdrojovy_uzol_socket, ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT, CIELOVY_UZOL_IP,
                      CIELOVY_UZOL_PORT):
    global data_queue, keep_alive_ack_received
    global syn_num
    global fin_num
    global hodnota_init_syn
    global sync
    global nazov_suboru, issue_sn
    global ciel_start_time_celkovy_cas_trvania_prenosu
    max_s_num = None
    msg_priebezny_pocet_spravne_prijatych_fragmetov = 0
    msg_celkovy_pocet_spravne_prijatych_fragmetov = 0
    msg_prijate_fragmenty_cache = {}
    file_celkovy_pocet_spravne_prijatych_fragmetov = 0
    file_priebezny_pocet_spravne_prijatych_fragmetov = 0
    file_prijate_fragmenty_cache = {}
    while True:

        hodnota = data_queue.get()
        typSpravyQueue = hodnota[0]
        data = hodnota[1]
        print(str(hodnota))

        if typSpravyQueue == "SYN":
            # spracovanie SYN spravy

            num = decap_syn_msg(data)
            odosli, hodnota_init_syn = encap_3w_msg(num)
            zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
            nastala_komunikacia_keep_a_live()

            print("Odosielam 3W SYN, ACK")

        if typSpravyQueue == "ACK":
            num = decap_ack(data)
            tmp = hodnota_init_syn + 1
            if tmp == num:
                print("3W HANDSHAKE USPESNY")
                # cas zaciatku merania prenusu po prijati prveho fragmentu
                ciel_start_time_celkovy_cas_trvania_prenosu = time.time()
            else:
                print("3W nema rovnaky seq sucet")
                break

        if typSpravyQueue == "3F":
            fin, ack = decap_3f_msg(data)
            tmp = fin_num + 1
            print(str(ack))
            if ack == tmp:
                odosli = encap_finack(fin)
                zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                nastala_komunikacia_keep_a_live()

                print("[ZDROJOVY UZOL] 3F HANDSHAKE done")
                print(f"{RED}[ZDROJOVY UZOL] Ukoncujem spojenie{RESET}")

            else:
                print("NEUSPESNY 3F sucet")
                exit(1)

        if typSpravyQueue == "PRVA_SPRAVA_FILE":
            max_s_num = decap_prva_data_sprava_file(data)
            print(f"Prva sprava presla, subor '{nazov_suboru}' bude prenasany v {str(max_s_num)} fragmentoch")

        if typSpravyQueue == "PRVA_SPRAVA_MSG":
            max_s_num = decap_prva_data_sprava_msg(data)
            print(f"Prva sprava presla, bude posielanych {str(max_s_num)} fragmentov")

        if typSpravyQueue == "DATA_MSG":
            # zo spravy, ktora pride, si zoberiem payload a vypocitam crc (bez headrov),
            # porovnam, ci su rovnake:
            # - ak su rovnake, ulozim ich do prijate_fragmenty_cache a
            # - ak nie su rovnake, robim append do issue_sn pola
            sn, fcs, msg = decap_data_msg(data)
            print(f"{BLUE}Prijaty fragment: {sn} {RESET}s typmto obsahom: " + str(msg))

            # vytvorime CRC pre obsah fragmentu, ktory sme prijali
            new_data_msg_CRC_checksum = int(msg_create_CRC_checksum_fragmentu(sn, msg), 16)
            print(f"Porovnanie CRC - CRC odoslanej spravy: {fcs}, CRC prijatej spravy:  {new_data_msg_CRC_checksum} ")

            # ak je rovnake CRC zo spravy a novo vypocitane CRC z obsahu prijateho fragmentu,
            # ulozim ich do msg_prijate_fragmenty_cache (zoznam korektne prijatych fragmentov)
            if fcs == new_data_msg_CRC_checksum:
                msg_priebezny_pocet_spravne_prijatych_fragmetov = msg_priebezny_pocet_spravne_prijatych_fragmetov + 1
                msg_celkovy_pocet_spravne_prijatych_fragmetov = msg_celkovy_pocet_spravne_prijatych_fragmetov + 1
                msg_prijate_fragmenty_cache[str(sn - 1)] = str(msg)
                print(f"Zaradenie fragmentu: {sn} do zoznamu uspesne prijatych fragmetov{RESET}")
                print(
                    f"Porovnanie CRC - CRC odoslanej spravy: {fcs}, CRC prijatej spravy:  {new_data_msg_CRC_checksum} ")
                print(f"{RUZOVA}Fragment: {sn} bol prijaty a preneseny bez chyb{RESET}")

            # ak nie je rovnake CRC zo spravy a novo vypocitane CRC z obsahu prijateho fragmentu,
            # ulozim ich do issue_sn (zoznam nepravne prijatych fragmentov)
            else:
                issue_sn.append(sn)
                msg_prijate_fragmenty_cache[str(sn - 1)] = None
                print(f"{RED}Fragment: {sn} bol preneseny s chybou - je zaradeny do zoznamu chybnych fragmetov{RESET}")

            if len(issue_sn) == 0:
                # RET spravu posielam po kazdom prijatom 5 fragmente
                if msg_priebezny_pocet_spravne_prijatych_fragmetov % 5 == 0:
                    print(f"{ORANZOVA}Odoslanie RET {RESET} spravy po prijati fragmentu: {sn}")
                    odosli = encap_ret_msg(issue_sn)
                    print("Obsah RET spravy: " + str(odosli))
                    zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                    nastala_komunikacia_keep_a_live()

                    msg_priebezny_pocet_spravne_prijatych_fragmetov = 0

                # ak som prijala posledny fragment, tak vypisem spravu
                if msg_celkovy_pocet_spravne_prijatych_fragmetov == max_s_num:
                    print(f"{ORANZOVA}Odoslanie RET {RESET} spravy po prijati posledneho fragmentu")
                    odosli = encap_ret_msg(issue_sn)
                    print("Obsah RET spravy: " + str(odosli))
                    zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                    nastala_komunikacia_keep_a_live()

                    print("Zacinam vyskladavat spravu z prijatych fragmentov")
                    vysledna_sprava = str(''.join(msg_prijate_fragmenty_cache.values()))

                    print("******* PRIJATA SPRAVA *****")
                    print(f"{GREEN}{vysledna_sprava}{RESET}")
                    print(f"{RUZOVA}Sprava bola uspesne prijata a vypisana o velkosti: {len(vysledna_sprava)}{RESET}")

                    print(f"{ORANZOVA}Odoslanie RET {RESET} spravy po prijati a vypisani spravy")
                    odosli = encap_ret_msg(issue_sn)
                    print("Obsah RET spravy: " + str(odosli))
                    zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                    nastala_komunikacia_keep_a_live()

                    # cas koncu merania prenusu po prijati posledneho fragmentu, vypisani spravy a odoslani potvrdenia
                    ciel_end_time_celkovy_cas_trvania_prenosu = time.time()
                    ciel_celkovy_cas_trvania_prenosu = ciel_end_time_celkovy_cas_trvania_prenosu - ciel_start_time_celkovy_cas_trvania_prenosu
                    print(f"{RUZOVA}[Cielovy uzol] - Celkovy cas trvania: {RESET}" + str(
                        ciel_celkovy_cas_trvania_prenosu))

                    # vynulovanie vsetkych potrebnych premennych
                    msg_prijate_fragmenty_cache = {}
                    kontrola = [None]
                    sum_poloha = 0
                    msg_priebezny_pocet_spravne_prijatych_fragmetov = 0
                    msg_celkovy_pocet_spravne_prijatych_fragmetov = 0
            else:
                # RET spravu posielam po kazdom prijatom 5 fragmente
                if (len(issue_sn) + msg_priebezny_pocet_spravne_prijatych_fragmetov) % 5 == 0:
                    print(f"{ORANZOVA}Odoslanie RET {RESET} spravy po prijati fragmentu: {sn}")
                    odosli = encap_ret_msg(issue_sn)
                    print("Obsah RET spravy: " + str(odosli))
                    zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                    nastala_komunikacia_keep_a_live()

                    msg_priebezny_pocet_spravne_prijatych_fragmetov = 0
                    issue_sn = []

                if len(issue_sn) + msg_celkovy_pocet_spravne_prijatych_fragmetov == max_s_num:
                    # RET spravu posielame po kazdom prijatom 5 fragmente
                    print(f"{ORANZOVA}Odoslanie RET{RESET} spravy po prijati fragmentu: {sn}")
                    odosli = encap_ret_msg(issue_sn)
                    print("Obsah RET spravy: " + str(odosli))
                    zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                    nastala_komunikacia_keep_a_live()

                    msg_priebezny_pocet_spravne_prijatych_fragmetov = 0
                    issue_sn = []

        if typSpravyQueue == "3W":
            num, ack_num = decap_3w_msg(data)
            if ack_num == syn_num + 1:

                odosli = encap_ack(num)
                zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                nastala_komunikacia_keep_a_live()

                print("[ZDROJOVY UZOL] 3W HANDSHAKE done")
                sync = 1

            else:
                print("NEUSPESNY 3W HANDSHAKE")
                exit(1)

        if typSpravyQueue == "DATA_FILE":
            # zo spravy, ktora pride, si zoberiem payload a vypocitam crc (bez headrov),
            # porovnam, ci su rovnake:
            # - ak su rovnake, ulozim ich do prijate_fragmenty_cache a
            # - ak nie su rovnake, robim append do issue_sn pola
            sn, fcs, msg = decap_data_msg(data)
            # print(f"{BLUE}Prijati fragment: {sn} {RESET}s typmto obsahom: " + str(msg))
            print(f"{BLUE}Prijati fragment: {sn} {RESET}")

            # vytvorim CRC pre obsah fragmentu, ktory som prijala
            new_data_file_CRC_checksum = int(file_create_CRC_checksum_fragmentu(sn, msg), 16)
            print(f"Porovnanie CRC - CRC odoslanej spravy: {fcs}, CRC prijatej spravy:  {new_data_file_CRC_checksum} ")

            # ak je rovnake CRC zo spravy a novo vypocitane CRC z obsahu prijateho fragmentu,
            # ulozim ich do msg_prijate_fragmenty_cache (zoznam korektne prijatych fragmentov)
            if fcs == new_data_file_CRC_checksum:
                file_priebezny_pocet_spravne_prijatych_fragmetov = file_priebezny_pocet_spravne_prijatych_fragmetov + 1
                file_celkovy_pocet_spravne_prijatych_fragmetov = file_celkovy_pocet_spravne_prijatych_fragmetov + 1
                file_prijate_fragmenty_cache[str(sn)] = str(msg)
                print(f"Zaradenie fragmentu: {sn} do zoznamu uspesne prijatych fragmetov{RESET}")
                print(f"{RUZOVA}Fragment: {sn} bol prijaty a preneseny bez chyb{RESET}")

            # ak nie je rovnake CRC zo spravy a novo vypocitane CRC z obsahu prijateho fragmentu,
            # ulozim ich do issue_sn (zoznam nespravne prijatych fragmentov)
            else:
                issue_sn.append(sn)
                file_prijate_fragmenty_cache[str(sn)] = None
                print(f"{RED}Fragment: {sn} bol preneseny s chybou - je zaradeny do zoznamu chybnych fragmetov{RESET}")

            if len(issue_sn) == 0:
                # RET spravu posielam po kazdom prijatom 5 fragmente
                if file_priebezny_pocet_spravne_prijatych_fragmetov % 5 == 0:
                    print(f"{ORANZOVA}Odoslanie RET{RESET} spravy po prijati fragmentu: {sn}")
                    odosli = encap_ret_msg(issue_sn)
                    print("Obsah RET spravy: " + str(odosli))
                    zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                    nastala_komunikacia_keep_a_live()

                    file_priebezny_pocet_spravne_prijatych_fragmetov = 0

                # ak som prijala posledny fragment, tak vypisem spravu
                if file_celkovy_pocet_spravne_prijatych_fragmetov == max_s_num:
                    # RET spravu posielam nie len po kazdom prijatom 5 fragmente ale aj po prijati posledneho fragmentu
                    print(f"{ORANZOVA}Odoslanie RET {RESET} spravy po prijati posledneho fragmentu spravy")
                    odosli = encap_ret_msg(issue_sn)
                    print("Obsah RET spravy: " + str(odosli))
                    zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                    nastala_komunikacia_keep_a_live()

                    print("Zacinam vyskladavat spravu z prijatych fragmentov")
                    pole_tmp = []
                    pozicia = 0

                    for i in file_prijate_fragmenty_cache:
                        # for jj in prijate_fragmenty_cache.values():
                        for qq in file_prijate_fragmenty_cache[str(pozicia)]:
                            pole_tmp.append(qq)
                        pozicia = pozicia + 1

                    index = 1
                    prijaty_vyskladany_obsah_suboru = ''.join(pole_tmp)
                    # file_name = nazov_suboru.split("'")[1]
                    file_ciel_name = nazov_suboru

                    print("******* PRIJATE DATA *****")
                    # print(f"{GREEN}{prijaty_vyskladany_obsah_suboru}{RESET}")
                    try:
                        p = base64.b64decode(prijaty_vyskladany_obsah_suboru)
                        with open(str(CIELOVY_ADRESA_PRE_ULOZENIE_SUBORU + "/" + file_ciel_name), "wb") as f:
                            f.write(p)
                            index += 1

                        file_path = Path(CIELOVY_ADRESA_PRE_ULOZENIE_SUBORU + "/" + file_ciel_name)
                        file_size = file_path.stat().st_size

                        print(f"{RUZOVA}Subor bol uspesne vytvoreny a data ulozene. Velkost supbru: {file_size}{RESET}")
                        print(
                            f"{RUZOVA}Subor bol ulozeny do adresara:{RESET} {CIELOVY_ADRESA_PRE_ULOZENIE_SUBORU} {RUZOVA}pod nazvom:{RESET} {file_ciel_name}")

                        print(f"{ORANZOVA}Odoslanie RET {RESET} spravy po prijati a ulozeni suboru")
                        odosli = encap_ret_msg(issue_sn)
                        print("Obsah RET spravy: " + str(odosli))
                        zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                        nastala_komunikacia_keep_a_live()

                        # cas koncu merania prenusu po prijati posledneho fragmentu, vypisani spravy a odoslani potvrdenia
                        ciel_end_time_celkovy_cas_trvania_prenosu = time.time()
                        ciel_celkovy_cas_trvania_prenosu = ciel_end_time_celkovy_cas_trvania_prenosu - ciel_start_time_celkovy_cas_trvania_prenosu
                        print(f"{RUZOVA}[Cielovy uzol] - Celkovy cas trvania: {RESET}" + str(
                            ciel_celkovy_cas_trvania_prenosu))

                        # vynulovanie vsetkych potrebnych premennych
                        file_prijate_fragmenty_cache = {}
                        file_priebezny_pocet_spravne_prijatych_fragmetov = 0
                        file_celkovy_pocet_spravne_prijatych_fragmetov = 0

                    except FileNotFoundError:
                        print(f"{RED}Cesta k umiestneniu suboru neexistuje. Skuste znova.{RESET}")
                    except PermissionError:
                        print(f"{RED}Nemate opravnenie zapisovat do zadaneho umiestnenia. Skuste znova.{RESET}")
                    except Exception as e:
                        print(f"{RED}Vyskytla sa neocakavana chyba{RESET}. Skuste znova.", e)

            else:
                # RET spravu posielam po kazdom prijatom 5 fragmente
                if (len(issue_sn) + file_priebezny_pocet_spravne_prijatych_fragmetov) % 5 == 0:
                    print(f"{ORANZOVA}Odoslanie RET {RESET} spravy po prijati fragmentu: {sn}")
                    odosli = encap_ret_msg(issue_sn)
                    print("Obsah RET spravy: " + str(odosli))
                    zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                    nastala_komunikacia_keep_a_live()

                    file_priebezny_pocet_spravne_prijatych_fragmetov = 0
                    issue_sn = []

                if len(issue_sn) + file_celkovy_pocet_spravne_prijatych_fragmetov == max_s_num:
                    # RET spravu posielam po kazdom prijatom 5 fragmente
                    print(f"{ORANZOVA}Odoslanie RET{RESET} spravy po prijati fragmentu: {sn}")
                    odosli = encap_ret_msg(issue_sn)
                    print("Obsah RET spravy: " + str(odosli))
                    zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
                    nastala_komunikacia_keep_a_live()

                    file_priebezny_pocet_spravne_prijatych_fragmetov = 0
                    issue_sn = []

        if typSpravyQueue == "FIN":
            num = decap_fin_msg(data)
            odosli, fin_num = encap_3f_msg(num)
            zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))  # posielam 3w
            print("[CIELOVY UZOL] Posielam 3F")
            print(f"{RED}[CIELOVY UZOL] Ukoncujem spojenie{RESET}")

        if typSpravyQueue == "FIN_ACK":
            num = decap_finack(data)
            print(str(num))
            tmp = fin_num + 1
            if tmp == num:
                print("3F HANDSHAKE USPESNY")
                print(f"{RED}UKONCUJEM SPOJENIE{RESET}")
                # exit()
                # break
            else:
                print("3F nema rovnaky seq sucet")
                break

        if typSpravyQueue == "RET":
            kontrola_poctu(data)

        if typSpravyQueue == "KEEP":
            num = dencap_keep_alive(data)
            odosli = encap_keep_alive_ack(num)
            zdrojovy_uzol_socket.sendto(odosli, (ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
            nastala_komunikacia_keep_a_live()

        if typSpravyQueue == "ACK_FOR_KEEP":
            try:
                keep_alive_ack_received = True
                num = dencap_keep_alive_ack(data)
                print(f"{AZUROVA}[KEEP_ALIVE ACK] so seq cislom: {num}{RESET}")
                # keep_alive_msg_array.clear()
                # print(f"[KEEP_ALIVE ACK] stack: {keep_alive_msg_array}")
            except socket.timeout:
                print("[KEEP_ALIVE ACK] Ziadna ACK sprava nebola dorucena pre keepalive")
            except ConnectionResetError:
                print("[KEEP_ALIVE ACK] Server uzavrel konekciu a spojenie")
                break
            except Exception as e:
                print(f"[KEEP_ALIVE ACK] nastala chyba pocas prijimania spravy ACK: {e}")


# funkcia pre cielovy uzol - prijima spravy
def start_CielovyUzol(cielovy_uzol_socket, zdrojovy_uzol_socket, ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT, CIELOVY_UZOL_IP,
                      CIELOVY_UZOL_PORT):
    global syn_num
    global fin_num
    global sync
    global data_queue

    print(f"Cielovy uzol bezi na porte {CIELOVY_UZOL_PORT}. Caka na spravy...")
    print(f"Zdrojovy uzol bezi na porte {ZDROJOVY_UZOL_PORT}. Caka na spravy...")
    # cielovy uzol bude pocuvat na vsetkych IP adresach na danom porte
    cielovy_uzol_socket.bind((CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT))

    while True:
        # addr IP, z ktorej prisla sprava
        data, addr = cielovy_uzol_socket.recvfrom(2048)  # cielovy uzol vie naraz precitat najviac 2048 bajtov
        unpacked_msg_type = struct.unpack('!c', data[:1])[0]  # vyberie 1. bajt (char) a vlozi ho do unpacked_msg_type
        # print(f"Prijata sprava od {addr}: {data}")

        if unpacked_msg_type == b's':
            data_queue.put(["SYN", data])

        if unpacked_msg_type == b'a':
            data_queue.put(["ACK", data])

        if unpacked_msg_type == b'x':
            data_queue.put(["DATA_MSG", data])

        if unpacked_msg_type == b'y':
            data_queue.put(["DATA_FILE", data])

        if unpacked_msg_type == b'w':
            data_queue.put(["3W", data])

        if unpacked_msg_type == b'k':
            data_queue.put(["3F", data])

        if unpacked_msg_type == b'f':
            data_queue.put(["FIN", data])

        if unpacked_msg_type == b'q':
            data_queue.put(["FIN_ACK", data])

        if unpacked_msg_type == b'p':
            data_queue.put(["PRVA_SPRAVA_FILE", data])

        if unpacked_msg_type == b't':
            data_queue.put(["PRVA_SPRAVA_MSG", data])

        if unpacked_msg_type == b'r':
            data_queue.put(["RET", data])

        if unpacked_msg_type == b'e':
            data_queue.put(["KEEP", data])

        if unpacked_msg_type == b'o':
            data_queue.put(["ACK_FOR_KEEP", data])


def start_ZdrojovyUzol(zdrojovy_uzol_socket, CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT):
    global syn_num
    global fin_num
    global sync
    global max_seq_num, zapiname_keep_alive
    sync = 0
    pociatok = 0
    global zbehla_prva, random_issue_sn

    while True:
        typ = input("Zadaj typ spravy 0- msg, 1- file: ")

        zapiname_keep_alive = 1
        if zapiname_keep_alive == 1:
            start_keepalive = threading.Thread(target=keepalive_thread, args=(
                cielovy_uzol_socket, zdrojovy_uzol_socket, CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT, ZDROJOVY_UZOL_IP,
                ZDROJOVY_UZOL_PORT))
            start_keepalive.daemon = True
            start_keepalive.start()

            while not keep_alive_queue.empty():
                keep_alive_queue.get()
            keep_alive_queue.put(["KEEP_ALIVE_START"])

        if typ == "0":
            message = input("Zadaj spravu na odoslanie: ")
            if message == "k":
                fin_num, odosli = encap_fin_msg()
                zdrojovy_uzol_socket.sendto(odosli, (CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT))
                nastala_komunikacia_keep_a_live()

                while not keep_alive_exit_queue.empty():
                    keep_alive_exit_queue.get()
                keep_alive_exit_queue.put(["KEEP_ALIVE_STOP"])

                time.sleep(SYSTEM_EXIT_TIMEOUT)
                sys.exit()
        else:
            file_zdroj_path = input("Zadaj cestu k suboru: ")
            file_zdroj_name = input("Zadaj subor: ")

            if file_zdroj_name == "k":
                fin_num, odosli = encap_fin_msg()
                zdrojovy_uzol_socket.sendto(odosli, (CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT))
                nastala_komunikacia_keep_a_live()

                while not keep_alive_exit_queue.empty():
                    keep_alive_exit_queue.get()
                keep_alive_exit_queue.put(["KEEP_ALIVE_STOP"])

                time.sleep(SYSTEM_EXIT_TIMEOUT)
                sys.exit()
            message = "0"

        mtu = int(input("Zadaj velkost dat v B bez headerov(35B) na odoslanie (max velkost 1465): "))
        if mtu > 1465:
            while mtu > 1465:
                print(f"{RED}Velkost fragmentu nemoze byt vacsia ako 1465.{RESET} Prosim zadajte mensiu hodnotu")
                mtu = int(input("Zadaj velkost dat v B bez headerov(35B) na odoslanie (max velkost 1465): "))
        issue = int(input("Pocet umelych chyb(Retransmisii): "))

        # cas zaciatku merania prenusu od potvrdenia poctu chyb
        zdroj_start_time_celkovy_cas_trvania_prenosu = time.time()

        if pociatok == 0:  # prva SYN sprava
            header_signal, syn_num = encap_syn_msg()
            zdrojovy_uzol_socket.sendto(header_signal, (CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT))
            nastala_komunikacia_keep_a_live()

            pociatok = 1

        zbehla_prva = 0
        while True:
            # najprv musi zbehnut handshake, ked zbehne handshake, sync = 1
            if sync == 1:
                if typ == "0":
                    max_seq_num = math.ceil(len(message) / mtu)
                    print(
                        f"{RUZOVA}Pocet fragmentov: {str(max_seq_num)}, dlzka spravy: {len(message)} / mtu: {mtu}{RESET}")

                    while not data_queue.empty():
                        data_queue.get()
                    while not ret_queue.empty():
                        ret_queue.get()

                    # na zaklade vstupnej hodnoty vytvorim pole s miestami, v ktorych fragmentoch budu umelo vytvorenene chyby
                    random_issue_sn = [None] * max_seq_num
                    random_issue_sn[1:max_seq_num] = [0] * max_seq_num
                    if issue > max_seq_num:
                        print(
                            f"{ORANZOVA}Pocet issue {str(issue)} bude zmeneny na hodnotu: {str(max_seq_num)}{RESET}, nemoze byt vacsi ako pocet vypocitanych fragmentov")
                        issue = max_seq_num
                    random_chybne_pozicie_fragmentov = generovat_cisla(1, max_seq_num, issue)
                    for random_pozicia in random_chybne_pozicie_fragmentov:
                        random_issue_sn[random_pozicia] = 1

                    # vypis pola s miestami, v ktorych fragmentoch budu umelo vytvorenene chyby
                    print("Fragmenty, ktore budu odoslielane ako chybne: \n" + str(random_issue_sn))

                    # poslanie prvej data sprava (obsahom je sekvencne cislo, aby nebolo posielane v kazdej datovej sprave)
                    encap_prva_data_sprava_msg(zdrojovy_uzol_socket, CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT, mtu,
                                               max_seq_num)
                    # poslanie spravy (data)
                    encap_data_msg(type_of_msg_data_con, zdrojovy_uzol_socket, CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT,
                                   message, mtu, max_seq_num)
                    break

                else:

                    file_path_file_name = file_zdroj_path + "/" + file_zdroj_name
                    file = open(file_path_file_name, "rb")
                    msg = base64.b64encode(file.read()).decode()
                    max_seq_num = math.ceil(len(msg) / (mtu))

                    file_path = Path(file_path_file_name)
                    file_size = file_path.stat().st_size

                    print(f"{RUZOVA}Nazov suboru: {str(file_zdroj_name)}{RESET}")
                    print(
                        f"{RUZOVA}Pocet fragmentov: {str(max_seq_num)}, velkost suboru: {file_size} / mtu: {mtu}{RESET}")

                    while not data_queue.empty():
                        data_queue.get()
                    while not ret_queue.empty():
                        ret_queue.get()

                    # na zaklade vstupnej hodnoty vytvorime pole s miestami, v ktorych fragmentoch budu umelo vytvorenene chyby
                    random_issue_sn = [None] * max_seq_num
                    random_issue_sn[1:max_seq_num] = [0] * max_seq_num
                    if issue > max_seq_num:
                        print(
                            f"{ORANZOVA}Pocet issue {str(issue)} bude zmeneny na hodnotu: {str(max_seq_num)}{RESET}, nemoze byt vacsi ako pocet vypocitanych fragmentov")
                        issue = max_seq_num
                    random_chybne_pozicie_fragmentov = generovat_cisla(1, max_seq_num, issue)
                    for random_pozicia in random_chybne_pozicie_fragmentov:
                        random_issue_sn[random_pozicia] = 1

                    # vypis pola s miestami, v ktorych fragmentoch budu umelo vytvorenene chyby
                    print("Fragmenty, ktore budu odoslielane ako chybne: \n" + str(random_issue_sn))

                    encap_prva_data_sprava_file(zdrojovy_uzol_socket, CIELOVY_UZOL_IP,
                                                CIELOVY_UZOL_PORT, mtu, max_seq_num, file_zdroj_name)

                    encap_data_file(type_of_msg_data_file, zdrojovy_uzol_socket, CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT,
                                    msg, mtu)  # odoslanie spravy na PC2
                    break
        zdroj_end_time_celkovy_cas_trvania_prenosu = time.time()
        zdroj_celkovy_cas_trvania_prenosu = zdroj_end_time_celkovy_cas_trvania_prenosu - zdroj_start_time_celkovy_cas_trvania_prenosu
        print(f"{RUZOVA}[Zdrojovy uzol] - Celkovy cas trvania: {RESET}" + str(zdroj_celkovy_cas_trvania_prenosu))


def generovat_cisla(od, do, pocet):
    if pocet > (do - od + 1):
        pocet = do
    return random.sample(range(od, do + 1), pocet)


def nastala_komunikacia_keep_a_live():
    global keep_alive_last_activity_time, keep_alive_msg_array
    # nastavenie, ze doslo ku komunikacii (nie sme off-line)
    keep_alive_last_activity_time = time.time()
    # vynulujeme pole, ktore obsahuje spravy keepalive
    keep_alive_msg_array.clear()


def convert_seconds_to_minutes(seconds):
    return seconds / 60


def keepalive_thread(cielovy_uzol_socket, zdrojovy_uzol_socket, CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT, ZDROJOVY_UZOL_IP,
                     ZDROJOVY_UZOL_PORT):
    global keep_alive_ack_received, keep_alive_seq_num, keep_alive_last_activity_time
    MESSAGE_SEND_INTERVAL = 5
    KEEPALIVE_INTERVAL = 5
    ACK_TIMEOUT = 5
    POCET_NEPRIJATYCH_ACK_KEEP_ALIVE_MSG = 3

    keep_alive_last_activity_time = time.time()

    while True:
        if zdrojovy_uzol_socket and not zdrojovy_uzol_socket._closed:

            if not keep_alive_queue.empty():
                keep_alive_hodnota = keep_alive_queue.get()
                typSpravyQueueKeepAlive = keep_alive_hodnota[0]
                print(typSpravyQueueKeepAlive)

                if typSpravyQueueKeepAlive == "KEEP_ALIVE_POSIELANIE_MSG_PRERUSENE" or typSpravyQueueKeepAlive == "KEEP_ALIVE_START":

                    keep_alive_seq_num = 0
                    while True:
                        start_time = time.time() - keep_alive_last_activity_time
                        pocet_minut_od_poslednej_necinnosti = start_time

                        # ak medzi zariadeniami neprebieha ziadna komunikacia po dobu 5s
                        if pocet_minut_od_poslednej_necinnosti > MESSAGE_SEND_INTERVAL:

                            keep_alive_ack_received = False
                            keep_alive_seq_num = keep_alive_seq_num + 1
                            header_signal, keep_alive_seq_num = encap_keep_alive(keep_alive_seq_num)
                            # odoslanie spravy kazdych 5s
                            zdrojovy_uzol_socket.sendto(header_signal, (CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT))
                            print(f"{AZUROVA}[KEEP_ALIVE] Odoslana poziadavka so seq: {keep_alive_seq_num}{RESET}")

                            keep_cas_zaciatku_cakania_na_odpoved = time.time()
                            pocet_minut_od_odoslania_keep_a_live_msg = 0

                            print(
                                f"{AZUROVA}[KEEP_ALIVE] Cakame na ACK KEEP A LIVE spravu, dlzka cakania: {RESET} {ACK_TIMEOUT} s")

                            # cakam 5s na ziskane ack keepalive spravy
                            while pocet_minut_od_odoslania_keep_a_live_msg < ACK_TIMEOUT:
                                if keep_alive_ack_received:
                                    # ak som obdrzala ack keepalive spravu, odstranim vsetky doteraz odoslane spravy
                                    # potrebujem mat suvisly nepreruseny sled 3 odoslanych keepalive sprav, aby som mohla spojenie ukoncit
                                    keep_alive_msg_array.clear()

                                    while not keep_alive_queue.empty():
                                        keep_alive_queue.get()

                                    keep_alive_queue.put(["KEEP_ALIVE_POSIELANIE_MSG_OBNOVENE"])

                                    break
                                keep_cas_cakania_na_odpoved = time.time()
                                pocet_minut_od_odoslania_keep_a_live_msg = keep_cas_cakania_na_odpoved - keep_cas_zaciatku_cakania_na_odpoved

                            if keep_alive_ack_received == False:
                                keep_alive_msg_array.append(keep_cas_zaciatku_cakania_na_odpoved)
                                print(f"{AZUROVA}[KEEP_ALIVE] stack: {RESET}{keep_alive_msg_array}")

                            if len(keep_alive_msg_array) == POCET_NEPRIJATYCH_ACK_KEEP_ALIVE_MSG:
                                print(
                                    f"{RED}Ukoncenie spojenia, pretoze sme neobdrzali odpovede na 3 po sebe odoslane AKC spravy {RESET}")
                                zdrojovy_uzol_socket.close()
                                break

                        if not keep_alive_exit_queue.empty():
                            keep_alive_exit_hodnota = keep_alive_exit_queue.get()
                            typSpravyQueueKeepAliveExit = keep_alive_exit_hodnota[0]
                            print(typSpravyQueueKeepAliveExit)

                            if typSpravyQueueKeepAliveExit == "KEEP_ALIVE_STOP":
                                break

                        time.sleep(KEEPALIVE_INTERVAL)


if __name__ == '__main__':
    # hostname mojho NTB
    hostname = socket.gethostname()
    ZDROJOVY_UZOL_IP = socket.gethostbyname(hostname)
    # ZDROJOVY_UZOL_IP = '127.0.0.1'
    print("IP zdrojoveho uzla: " + ZDROJOVY_UZOL_IP)

    # CIELOVY_UZOL_IP = "172.20.10.6"
    # CIELOVY_UZOL_IP = "192.168.1.45"
    # CIELOVY_UZOL_IP = "195.28.111.11"
    CIELOVY_UZOL_IP = input("Zadajte IP cieloveho uzla:")
    CIELOVY_UZOL_PORT = int(input("Zadajte PORT cieloveho uzla:"))
    ZDROJOVY_UZOL_PORT = int(input("Zadajte PORT zdrojoveho uzla:"))

    zdrojovy_uzol_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # vytvorenie UDP socketu pre zdrojovy uzol
    cielovy_uzol_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    start_CielovyUzol = threading.Thread(target=start_CielovyUzol, args=(
        cielovy_uzol_socket, zdrojovy_uzol_socket, CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT, ZDROJOVY_UZOL_IP,
        ZDROJOVY_UZOL_PORT))
    start_CielovyUzol.daemon = True
    start_CielovyUzol.start()

    send_ZdrojovyUzol = threading.Thread(target=sent_ZdrojovyUzol,
                                         args=(
                                             cielovy_uzol_socket, zdrojovy_uzol_socket, CIELOVY_UZOL_IP,
                                             CIELOVY_UZOL_PORT, ZDROJOVY_UZOL_IP, ZDROJOVY_UZOL_PORT))
    send_ZdrojovyUzol.daemon = True
    send_ZdrojovyUzol.start()
    start_ZdrojovyUzol(zdrojovy_uzol_socket, CIELOVY_UZOL_IP, CIELOVY_UZOL_PORT)
