# Klasifikace SSH
Protokol SSH (Secure Shell) je jedním z nejpoužívanějších protokolů služby vzdáleného přístupu ke konzoli počítačů připojených k počítačové síti. Navíc, protokol ale dovoluje i přenášení souborů či tunelování portů. Samotná komunikace v rámci protokolu SSH je šifrovaná a je považována za bezpečnou. Nicméně, z důvodu špatného nastavení SSH serverů, či slabých administrátorských hesel, je SSH častým cílem útočníků kteří se pokouší prolomit heslo pomocí útoků hrubou silou. I proto je vhodné vytvořit klasifikátor schopný anotovat SSH spojení (například přiřazovat štítek úspěšné/neúspěšné přihlášení), čímž pomůže identifikovat útočící IP adresy napříč celou spravovanou sítí.

## Požadavek na vstupní data

SSH klasifikátor vyžaduje na vstupu síťové toky ve formátu UniRec. Síťové toky musí být obohaceny o sekvenci délek paketů, jejich směrů, časových značek, a TCP příznaků. Dále, pro spolehlivé rozpoznávání SSH komunikace musí toky obsahovat i prvních 100 Bajtů přenesených dat. V poslední řadě jsou potřeba i histogramy obsahující distribuci délek paketů a mezi paketových mezer v rámci síťového toku. Minimální množina informačních polí pro korektní funkcionalitu modulu je:
```
DST_IP, SRC_IP, BYTES, BYTES_REV, TIME_FIRST, TIME_LAST, PACKETS, PACKETS_REV, DST_PORT, SRC_PORT, PROTOCOL, TCP_FLAGS, TCP_FLAGS_REV, IDP_CONTENT, IDP_CONTENT_REV, PPI_PKT_DIRECTIONS, PPI_PKT_FLAGS, PPI_PKT_LENGTHS, PPI_PKT_TIMES, D_PHISTS_IPT, D_PHISTS_SIZES, S_PHISTS_IPT, S_PHISTS_SIZES
```
Modul je implementován v jazyce Python a je navržen pro proudové zpracování síťových toků. Dochází tedy k minimálnímu ukládání mezivýsledků a využívání vyrovnávacích pamětí tak, aby byl nasaditelný i do velkých monitorovacích infrastruktur. Samotná architektura modulu se skládá z celkem pěti částí: Filtrování, Klasifikace Message Authentication Code (MAC), Autentizační detektor, Detektor časování a Detektor typu provozu. V následujících sekcích jsou funkcionality jednotlivých částí klasifikátoru popsány podrobněji.

### Filtrování

Filtrovací blok provádí selekci pouze relevantních síťových toků. V tomto případě provádí selekci toků přenášející komunikaci SSH. Na začátku spojení pomocí SSH je nešifrovaně přenášen textový řetězec identifikující verzi protokolu SSH (např. SSH-2.0-OpenSSH_9.3), čehož lze využít pro rozpoznání. Pokud síťový tok neobsahuje výše popsaný textový řetězec, je vyhodnocen jako irelevantní a není připuštěn k další klasifikaci z důvodu úspory výpočetní zdrojů.

### Klasifikace MAC

SSH protokol podporuje velké množství algoritmů kryptografické ochrany. Výběr samotného algoritmu se provádí během navazování spojení na základě nastavených preferencí na straně klienta a serveru. Použitý algoritmus kryptografické ochrany má následně velký vliv na velikost přenášených paketů a samotný tvar provozu. Velikosti a tvar provozu jsou ale nezbytné k analýze SSH v následujících blocích. A proto byl vyvinut klasifikátor MAC, který dokáže přesně odhadnout použité šifrování z velikostí síťových paketů. Tato informace je dále distribuována dalším detektorům, které si adaptují rozpoznávací konstanty a provedou přesnější klasifikaci.

Samotný MAC klasifikátor je realizován pomocí strojového učení. V rámci rozsáhlých experimentů dosahoval nejlepších výsledků algoritmus Random Forest, sestavený z pěti rozhodovacích stromů o maximální hloubce 42. Tento algoritmus dokázal správně určit použitou šifru v cca 90 % případů.

### Autentizační detektor

Autentizační detektor rozpoznává vzory komunikace během přihlašování. Po důkladném nastudování SSH protokolu byla navržena sada podmínek rozpoznávající komunikační vzory při úspěšném přihlášení. Tyto podmínky pracují s posloupností velikostí a směrů zašifrovaných paketů. V rámci práce s velikostmi paketů je i využívána informace z Klasifikátoru MAC, která pomáhá adaptovat konstanty očekávaných velikostí paketů. Autentizační detektor dokáže v případě dodržení specifikace SSH protokolu s přesností 100 % rozpoznat úspěšné a neúspěšné přihlášení. Navíc, na základě délek paketů obsahující autentizaci uživatele dokáže detektor odhadnout, zda se uživatel přihlašoval heslem, či veřejným klíčem.

### Detektor časování

Detektor časování se pokouší detekovat přihlašovací automaty a k tomu využívá rychlost uživatele při zadávání hesla. Pokud je zadávání hesla příliš rychlé, detektor jej vyhodnotí jako automatický nástroj. Minimální prodleva pro zadávání hesla člověkem byla nastavena na 1 sekundu. Hodnota byla určena na základě našeho výzkumu i informací z odborných publikací.

  

### Detektor typu provozu

Na základě informací o množství přenesených dat a histogramů délek i mezi paketových intervalů dokáže klasifikátor odvodit i typ SSH provozu. V současné chvíli je možné spolehlivě rozpoznat tři druhy provozu. Stahování, Nahrávání souborů a využívání vzdáleného terminálu.

###  Výstup modulu

Výstup klasifikátoru se skládá z původně přijatých informací síťového toku obohacený o další kontextové informace o SSH spojení. Kontextové informace lze rozdělit do čtyř kategorií: Výsledek autentizace, Typ použité autentizace, Časová analýza autentizace a Typ SSH provozu. Podrobné výstupní štítky jsou zaneseny v následující Tabulce:

| Kategorie (Název UniRec Políčka)                   | Štítek   | Popis                                                                             |
|----------------------------------------------------|----------|-----------------------------------------------------------------------------------|
| Výsledek autentizace(AUTHENTICATION_RESULT)        | fail     | Neúspěšné přihlášení                                                              |
|                                                    | auth_ok  | Úspěšné přihlášení                                                                |
|                                                    | unknown  | Nepodařilo se rozpoznat                                                           |
| Typ použité autentizace (AUTHENTICATION_METHOD)    | key      | Přihlášení klíčem                                                                 |
|                                                    | password | Přihlášení heslem                                                                 |
|                                                    | unknown  | Nepodařilo se rozpoznat                                                           |
| Časová analýza autentizace (AUTHENTICATION_TIMING) | user     | Přihlašoval se uživatel                                                           |
|                                                    | auto     | Přihlašoval se automat                                                            |
|                                                    | unknown  | Nepodařilo se rozpoznat                                                           |
| Typ SSH provozu (TRAFFIC_CATEGORY)                 | upload   | Došlo k uploadu dat (příkaz scp)                                                  |
|                                                    | download | Došlo k downloadu dat (příkaz scp)                                                |
|                                                    | terminal | Využití interaktivního terminálu                                                  |
|                                                    | other    | Další kategorie (port tunneling, automatické připojení s jedním příkazem a další) |
|                                                    | unknown  | Nepodařilo se detekovat typ provozu (např. při neúspěšném přihlášení)             |


### Testování

Testování klasifikátoru v rámci testovacího nasazení na síti CESNET3. V průběhu 3 měsíců byly vyhodnocovány výstupy klasifikátoru. Klasifikátor fungoval korektně s uspokojující přesností. Klasifikace úspěšnosti přihlášení vycházela s přesností 99.6%. V rámci testování na síti CESNET3 bylo nicméně zjištěno, že velká část zařízení neimplementuje korektně standard protokolu SSH, čímž se snižuje přesnost detekce úspěšného vs. neúspěšného přihlášení. Proto bylo i v rámci této fáze provedeno několik úprav v detekci pro snížení hlášení falešně úspěšných přihlášení.

