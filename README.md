# Sada klasifikačních modulů pro detekci bezpečnostních hrozeb  

Cílem tohoto softwarového řešení je vytvořit první produkčně použitelné klasifikátory šifrovaného provozu založené na strojovém učení. Technologie strojového učení má potenciál výrazně zlepšit schopnost klasifikace šifrovaného síťového provozu, což má klíčový význam pro identifikaci bezpečnostních hrozeb a zajištění povědomí o situaci na počítačové síti.

V průběhu prvního roku realizační fáze projektu byly ve spolupráci s aplikačním garantem identifikovány typy bezpečnostních hrozeb či vhodné případy užití klasifikace síťového provozu pro zacílení výsledku V3. V rámci intenzivního výzkumu prováděného a validovaného napříč všemi organizacemi konsorcia řešitelů byly vyvinuty první funkční vzorky, pro ověření konceptu klasifikace. Tyto funkční vzorky využívaly inovativního přístupu, například pomocí slabých indikátorů a jejich klasifikační přesnost často převyšovala předchozí relevantní práce. I proto se v rámci práce na výsledku V3 podařilo publikovat řadu odborných článků v prestižních časopisech, či na prestižních mezinárodních konferencích.

Na základě výsledků výzkumu a ve spolupráci s aplikačním garantem bylo následně upřesněno, že se Sada klasifikačních modulů pro detekci bezpečnostních hrozeb bude skládat z následujících pěti částí:

1.  Klasifikátor SSH spojení
2.  Klasifikace TLS služeb
3.  Klasifikace QUIC služeb
4.  Detekce síťových tunelů
5.  Detekce těžby kryptoměn
    

Vybrané moduly byly v průběhu druhého roku řešení projektu dále vylepšovány ze strany klasifikační přesnosti, rychlosti klasifikace, či udržitelnosti kódu. Pro efektivní proudové zpracování síťových dat bylo využito systému NEMEA, který umožní jednoduché začlenění klasifikátorů jak v rámci sdružení CESNET tak aplikačního garanta. Dále byla navíc vyvinuta i znovupoužitelná soustava funkcí a metod (framework), která usnadní vývoj nových klasifikačních algoritmů v budoucnosti, což umožní rychleji reagovat na nové bezpečnostní hrozby a vyvíjející se požadavky aplikačního garanta a dalších potenciálních uživatelů.

Vytvořený výsledek V3 byl úspěšně nasazen a otestován v reálném prostředí sítě CESNET3, která denně připopuje více než půl milionu uživatelů k internetu. Navíc, byl za účelem prezentace funkcionality výsledku V3 vytvořen obraz virtuálního stroje (Virtual Machine), obsahující vyvinuté klasifikační a detekční algoritmy a ukázková vstupní data pro otestování a předvedení korektní funkčnosti. I přes plánovaný další rozvoj a vylepšování dosaženého výsledku V3 v dalším období realizační fáze projektu je tato sada softwarových modulů schopna efektivně klasifikovat síťový provoz a identifikovat v něm množinu síťových bezpečnostních hrozeb. Výsledek je použitelný dokonce i v rámci vysokorychlostních sítí, což bylo otestováno právě v národní síťové infrastruktuře CESNET3. Díky tomu dosažený výsledek dokáže ochránit nejen provoz kritických síťových infrastruktur, ale i velké množství uživatelů připojených do sítě.

## Struktura výsledku a demonstrační virtuální počítač
Sada klasifikačních modulů pro detekci bezpečnostních hrozeb je dostupná v rámci archivu obsahující zdrojové kódy, instalační skripty a ukázková data.

```
    .
    ├── LICENSE……………………………………………………………………………………………………………………………Licenční…soubor
    ├── README.md……………………………………………………………………………………………………………………………Readme…soubor
    ├── Vagrantfile…………………………………………………………Soubor…s…definicí…virtuálního…stroje
    ├── clfs
    │ ├── crypto-clf…………………………………………………………………………………Detektor…těžby…kryptoměn
    │ ├── ssh-clf………………………………………………………………………………………………………………Klasifikátor…SSH
    │ ├── tunnel-clf…………………………………………………………………………………Detektor…síťových…tunelů
    │ └── webservice-clf…………………………………………Klasifikátory…TLS…a…QUIC…komunikace
    ├── global_dependencies………………………Složka…se…závislostmi…nutnými…k…instalaci
    │ ├── rpm
    │ └── yum-packages
    └── install-fetav3.sh……………………………………………………………………………………………Instalační…skript
```

Archiv rovněž obsahuje soubor Vagrantfile obsahující definici virtuálního počítače, který slouží k demonstračním účelům. Po zapnutí virtuálního stroje pomocí příkazu vagrant up v příkazové řádce, dojde rovnou k instalaci závislostí potřebných pro běh jednotlivých klasifikačních modulů. Jedná se zejména o systém NEMEA, jazyk Python a standardní knihovny pro strojové učení jako PyTorch a SciKit Learn. Po instalaci závislostí dojde rovněž k instalaci samotných modulů. Instalace modulů vytvoří v domovském adresáři uživatele skripty, které slouží k jednoduchému spuštění modulů na demonstračních datech. Výpis domovského adresáře s jednotlivými demonstračními skripty je zde:
```
    [vagrant@oracle8 ~]$ ls
    run-miner-det.sh run-tunnel-visualiser.sh run-webservice-tls.sh
    run-ssh.sh run-webservice-evaluation.sh
    run-tunnel-det.sh run-webservice-quic.sh
```
## Vstupní data

Sada klasifikačních modulů je navržena s cílem nasazení na kolektoru síťových toků, standardním článku monitorovací infrastruktury založené na síťových tocích. Server Kolektor shromažďuje toky ze síťových sond, které jsou distribuovány pomocí přenosového protokolu IPFIX. Software kolektor přijímá IPFIX a zpracovává IPFIX data a přeposílá je k další analýze pomocí modulů. Pro distribuci dat v rámci serveru Kolektor je uvažován systém NEMEA (Network Measurement Analysis)

NEMEA je proudově orientovaný a modulární detekční systém pro analýzu síťových toků. V praxi se jedná o množinu nezávislých modulů které přijímají, zpracovávají a odesílají data v reálném čase. Samotné NEMEA moduly pak realizují různorodé funkce od jednoduché filtrace toků až po složité detekce vzorů podezřelého síťového provozu pomocí strojového učení. Výsledek V3 je realizován ve formě sady NEMEA modulů.

  

NEMEA systém umožňuje interakci mezi různými moduly a přenáší data ve formátu UniRec záznamů. UniRec záznamy jsou tabulárně strukturovaná data, kde každý řádek reprezentuje jeden IP tok. Informace přenášené v jednotlivých UniRec záznamech jsou seskupeny v následující tabulce—jedná se o všechny informace poskytované sondou k danému toku. V rámci práci na výstupu jsme ovšem implementovali i rozšíření přímo do sondy, které poskytují důležité informace pro modul detekce síťových tunelů. Jednotlivé navržené moduly následně tato data konzumují a rozšiřují o informace na základě výsledků analýzy.

| Název               | Popis                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------ |
| DST_IP              | Adresa cíle                                                                                |
| SRC_IP              | Adresa zdroje                                                                              |
| BYTES               | Počet přenesených bajtů od zdroje do cíle                                                  |
| BYTES_REV           | Počet přenesených bajtů od cíle do zdroje                                                  |
| TIME_FIRST          | Časová značka prvního paketu                                                               |
| TIME_LAST           | Časová značka posledního paketu                                                            |
| PACKETS             | Počet přenesených paketů od zdroje do cíle                                                 |
| PACKETS_REV         | Počet přenesených paketů od cíle do zdroje                                                 |
| DST_PORT            | Cílový port                                                                                |
| SRC_PORT            | Zdrojový port                                                                              |
| PROTOCOL            | Protokol transportní vrstvy                                                                |
| TCP_FLAGS           | Logický OR TCP příznaků přenesených od zdroje do cíle                                      |
| TCP_FLAGS_REV       | Logický OR TCP příznaků přenesených od cíle do zdroje                                      |
| IDP_CONTENT         | Prvních 100 bajtů z prvního datového paketu přeneseného od zdroje do cíle                  |
| IDP_CONTENT_REV     | Prvních 100 bajtů z prvního datového paketu přeneseného od cíle do zdroje                  |
| PPI_PKT_DIRECTIONS  | Pole indikující jednotlivé směry prvních 30 paketů                                         |
| PPI_PKT_LENGTHS     | Pole indikující jednotlivé délky prvních 30 paketů                                         |
| PPI_PKT_TIMES       | Pole časových značek prvních 30 paketů                                                     |
| PPI_PKT_FLAGS       | Pole TCP příznaků nastavených v prvních 30 paketech                                        |
| D_PHISTS_IPT        | Histogram distribuce mezipaketových intervalů v rámci paketů přenesených od cíle ke zdroji |
| D_PHISTS_SIZES      | Histogram distribuce paketových délek v rámci paketů přenesených od cíle ke zdroji         |
| S_PHISTS_IPT        | Histogram distribuce mezipaketových intervalů v rámci paketů přenesených od zdroje k cíli  |
| S_PHISTS_SIZES      | Histogram distribuce paketových délek v rámci paketů přenesených od zdroje k cíli.         |
| TLS_SNI             | Doménové jméno přenesené v rámci TLS Server Name Indication                                |
| TLS_JA3_FINGERPRINT | JA3 otisk klienta                                                                          |
| QUIC_SNI            | Doménové jméno přenesené v rámci QUIC Server Name Indication                               |
| QUIC_UA             | User Agent přenesený v rámci QUIC Client Hello                                             |




