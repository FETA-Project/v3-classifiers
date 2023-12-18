# Detekce síťových tunelů
Síťový tunel je technika, která dovoluje přenášet data jednoho spojení skrz spojení jiné. Může se jednat o Virtuální Privátní Sítě (VPN), nebo také o anonymizační službu TOR. V praxi to může, mimo jiné, znamenat obcházení firewall politik a jiných bezpečnostních opatření, či cílenou exfiltraci dat. Škodlivý software (malware, spyware, a další) může tuto techniku použít pro komunikaci se svým řídícím serverem (tzv. command&control server) a získávat nové instrukce. Může také exfiltrovat získaná data, kryptografické klíče (ransomware), šířit se dál apod. Data původního spojení jsou “zapouzdřena” do paketů spojení nového. Data jsou většinou také zašifrována, což snižuje viditelnost do provozu a komplikuje rozhodování o tom, zda provoz je či není škodlivý.

Detektor síťových tunelů používá porty a blocklist dodaný uživatelem. Dále používá informace z detektoru TOR spojení, detektoru sekvence příznaků SYN-SYNACK-ACK (SSA) a detektorů OpenVPN a WireGuard (popsány níže). Na vstupu je seznam IP rozsahů, pro které detektor sleduje jednotlivé indikátory. Po vypršení časového okna (15 min) se provede samotná detekce—pro každou sledovanou IP adresu se aplikují pravidla a pokud je pravidlo splněno, detektor pošle na výstupní interface zprávu.

## Požadavek na vstupní data
Detektor síťových tunelů na vstupu vyžaduje síťové toky ve formátu UniRec. Vstupní síťové toky musí, kromě základních políček, obsahovat také výstupy detektorů OpenVPN (OVPN_CONF_LEVEL), WireGuard (WG_CONF_LEVEL) a SSA (SSA_CONF_LEVEL), umístěné přímo v sondě, a výstup detektoru protokolu TOR (TOR_DETECTED), který byl vyčleněn do samostatného modulu a je popsán níže v sekci Architektura Modulu. Požadované vstupní pole z jsou:
```
SRC_IP, DST_IP, SRC_PORT, DST_PORT, TIME_LAST
```
## Architektura Modulu
Detektor na vstupu přijímá jednotlivé síťové toky, ze kterých zpracuje informace a provede detekci na základě portů a IP adres. Všechny tyto informace se uloží k již dříve získaným informacím k dané IP adrese (pokud ani jedna IP adresa nepatří do jednoho ze sledovaných IP rozsahů chráněné infrastruktury, dojde k zahození toku—nezpracovává se). Z aktuálně zpracovávaného síťového toku se také extrahuje aktuální časová značka (pole TIME_LAST).

Detektor využívá knihovnu WIF (popsaná v sekci Detekce těžby kryptoměn) a zároveň používá výstupy detektorů, které jsou umístěny přímo v sondě, a výstup TOR detektoru.

### Detekce OpenVPN
Detektor protokolu OpenVPN pracuje s jednotlivými pakety přímo na síťové sondě a kontroluje první bajt každého paketu, který obsahuje typ OpenVPN paketu. Detektor rozpoznává OpenVPN komunikaci tak, že analyzuje sekvenci typů paketů odeslaných v rámci toku. Pokud tato sekvence odpovídá sekvenci navazování OpenVPN spojení, detektor vyhodnotí tok jako OpenVPN s pravděpodobností 100 % . 

Pokud jsou příznaky konstantní, s hodnotou označující pouze datový paket, detektor vyhodnotí datové tok jako OpenVPN s pravděpodobností 80 %. V ostatních případech detektor neoznačuje tok jako OpenVPN, pravděpodobnost je tedy 0 %. Výstupem detektoru je políčko OVPN_CONF_LEVEL, které obsahuje pravděpodobnost, že daný tok obsahoval OpenVPN komunikaci.

### Detekce WireGuard
Detektor protokolu WireGuard pracuje s protokolovou hlavičkou. Pokud je hlavička protokolu WireGuard úspěšně naparsována, detektor vyhodnotí tok jako WireGuard s pravděpodobností 100 %. V ostatních případech detektor neoznačuje tok jako WireGuard, pravděpodobnost je tedy 0 %.
Výstup detektoru je zanesen v políčka WIREGUARD_CONF_LEVEL, které obsahuje pravděpodobnost, že daný tok obsahoval WireGuard komunikaci.

### Detekce SSA sekvence

SSA (Syn SynAck Ack) je sekvence TCP příznaků, která je odesílána během navazování TCP spojení. Server a klient si touto sekvencí dohodnou spojení, pomocí kterého následně komunikují. V rámci síťových tunelů obvykle dochází k posílání TCP spojení uvnitř UDP tunelu. Detektor SSA sekvence tedy sleduje UDP komunikaci a snaží se rozpoznat sekvenci délek paketů, která odpovídá SSA sekvenci. 

Samotná detekce je realizována konečným automatem, který hledá v čase větší množství změn velikostí odpovídající SSA sekvencí v rámci jedné UDP komunikace. Výstupem modulu je políčko SSA_CONF_LEVEL, které obsahuje míru jistoty, že je uvnitř UDP komunikace tunelováno TCP spojení.

### Detekce protokolu TOR

Detektor protokolu TOR využívá WIF klasifikátor, který kontroluje, zda se IP adresy síťových toků vyskytují na zadaném blocklistu IP adres. Pokud je alespoň jedna IP adresa (zdrojová IP adresa, cílová IP adresa) nalezena na blocklistu, síťový tok je považován za TOR komunikaci. Detektor navíc sleduje čas poslední změny blocklist souboru na disku. Pokud je detekována nová verze, detektor ji automaticky načte a výstupy detekce tak zůstávají aktuální.

Blocklist obsahující aktualizovaný seznam TOR uzlů je přístupný přímo na stránkách TOR projektu ([https://onionoo.torproject.org/summary?running=true](https://onionoo.torproject.org/summary?running=true)). V přiložených zdrojových kódech je i skript, který dokáže tento seznam stáhnout a připravit do správného formátu. S pomocí linuxového plánovače úloh (cron) se tedy dá např. jednou denně stáhnout nová verze blocklistu, kterou si detektor poté automaticky načte.

Detektor zpracovává síťové toky ve formátu UniRec, jeden po druhém. Potřebná UniRec políčka jsou SRC_IP a DST_IP. Pro každý tok je provedena detekce a na výstup je poslána kopie vstupních políček obohacená o následující dvě políčka: TOR_DETECTED a TOR_DIRECTION. Výstupní políčka jsou popsána v následující Tabulce .

| Název UniRec Políčka | Hodnota | Popis                           |
|----------------------|---------|---------------------------------|
| TOR_DETECTED         | 0       | TOR nebyl detekován             |
|                      | 1       | TOR byl detekován               |
| TOR_DIRECTION        | 0       | TOR uzel nebyl v žádném políčku |
|                      | \-1     | TOR uzel byl v SRC_IP           |
|                      | 1       | TOR uzel byl v DST_IP           |

## Detektor síťových tunelů

Detektor síťových tunelů tedy používá výsledky dalších detektorů jako jednotlivé indikátory. Konkrétně detektor OpenVPN (OVPN), WireGuard (WG), SSA a TOR. Detektor navíc sám provádí detekci výchozích portů OpenVPN a WireGuardu. Navíc má na vstupu definovány IP rozsahy, pro které se má detekce provádět. Slabé detektory si poté drží informace o svých indikátorech pro každou IP adresu ze vstupních adresních rozsahů.

Podobně jako detektor těžby kryptoměn je složen z několika slabých detektorů—každý zpracovává konkrétní indikátor. Slabé detektory OVPN, WG a SSA zpracovávají indikátory, které mají charakter pravděpodobnosti. Umožňují nastavit minimální práh pravděpodobnostní hodnoty. U slabých detektorů pro výchozí porty lze nastavit minimální počet toků, které obsahovaly v časovém okně alespoň v jednom z SRC_PORT a DST_PORT výchozí port dané VPN—1194 pro OVPN a 51820 pro WG. Slabý detektor protokolu TOR funguje obdobně, sleduje počet toků, které měly políčko TOR_DETECTED nastavené na hodnotu 1.

Z přijatého síťového toku se extrahuje aktuální čas z políčka TIME_LAST. Pokud od začátku aktuálního časového okna uplynulo více než 900 sekund (výchozí hodnota odpovídá 15 minutám, ale může být nastavena pomocí argumentu), detektor začne na jednotlivé indikátory aplikovat definovaná pravidla. Základní pravidlo má definovaný minimální počet viděných toků s danou charakteristikou a kontroluje, zda skutečný počet viděných toků tento limit přesáhl (např. pravidlo je splněno, pokud je minimální počet toků s OVPN_CONF_LEVEL > 90% alespoň 5, a slabý detektor pro danou IP adresu takových toků viděl 7). Limity pro každý slabý detektor je možné nastavit pomocí argumentu. Aktuální seznam aplikovaných pravidel je v následující Tabulce. O každém splněném pravidle je odeslána zpráva na výstupní interface. Poté dojde k vymazání uložených indikací v každém detektoru a proces začíná od začátku.

| Pravidlo                              | Popis                                                             |
| ------------------------------------- | ----------------------------------------------------------------- |
| OVPN_CONF_LEVEL == 100                | Alespoň jeden tok obsahoval OVPN pravděpodobnost rovnou 100 %     |
| OVPN_CONF_LEVEL AND SSA_CONF_LEVEL    | OVPN a SSA conf level detektory byly pozitivní                    |
| WG_CONF_LEVEL AND SSA_CONF_LEVEL      | WG a SSA conf level detektory byly pozitivní                      |
| OVPN_CONF_LEVEL AND OVPN_DEFAULT_PORT | Detektory OVPN conf levelu a  výchozího OVPN portu byly pozitivní |
| WG_CONF_LEVEL AND WG_DEFAULT_PORT     | Detektory WG conf levelu a  výchozího WG portu byly pozitivní     |
| TOR                                   | TOR detektor byl pozitivní                                        |
| BLOCKLIST                             | Byla detekována komunikace s adresou z uživatelského blocklistu   |


##### Výstup modulu

Výstup detektoru síťových tunelů obsahuje informace o detekovaných síťových tunelech na každé sledované IP adrese. Výstupní UniRec zpráva obsahuje IP adresu, na které byl síťový tunel detekován a popis splněného pravidla. Zpráva dále obsahuje informaci o každém ze slabých detektorů—zda daný detektor označil IP adresu pozitivně nebo ne a zároveň vysvětlení proč (obsahuje informace o tom, kolik toků splňující minimální podmínky slabý detektor v časovém okně viděl). Pole obsahující, zda výsledek detektoru byl pozitivní/negativní, se jmenují následovně—RESULT_%NÁZEV_DETEKTORU%. Zdůvodnění výsledku daného detektoru je dostupné v polích s názvy EXPLANATION_%NÁZEV_DETEKTORU%. Výstupní šablona detektoru síťových tunelů tedy vypadá následovně:
```
SRC_IP, RULE, DETECT_TIME, RESULT_PORT_OVPN, RESULT_PORT_WG, RESULT_CONF_LEVEL_OVPN, RESULT_CONF_LEVEL_WG, RESULT_CONF_LEVEL_SSA, RESULT_TOR, RESULT_BLOCKLIST, EXPLANATION_PORT_OVPN, EXPLANATION_PORT_WG, EXPLANATION_CONF_LEVEL_OVPN, EXPLANATION_CONF_LEVEL_WG, EXPLANATION_CONF_LEVEL_SSA, EXPLANATION_TOR, EXPLANATION_BLOCKLIST
```

## Testování

Detektor síťových tunelů byl od prvotních verzích nasazován na testovacím serveru s živými daty ze sítě CESNET3. V rámci tohoto vývoje byly několikrát přenastaveny minimální pravděpodobnostní prahy a minimální počty síťových toků s daným příznakem k tomu, aby byl výstup slabého detektoru pozitivní. Poté byly 5 měsíců sledovány výstupní zprávy tohoto detektoru s pečlivým zkoumáním toho, proč bylo konkrétní pravidlo splněno a IP adresa hlášena jako adresa komunikující skrz síťový tunel. V neposlední řadě se také několik pracovníků projektu připojovalo ze svého domova do sítě CESNET3 skrze síťový tunel WireGuard a testovali, zda budou detektorem nahlášeni—komunikace všech těchto pracovníků byla nahlášena jako síťový tunel.
