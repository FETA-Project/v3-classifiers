# Klasifikace webových služeb
## Klasifikace TLS služeb

TLS protokol je jeden z nejdůležitějších Internetových protokolů pro šifrovanou komunikaci a používá se například k přenosu webového provozu protokolu HTTP/2. Průběh šifrované TLS komunikace lze rozdělit na dvě hlavní části – úvodní navázání zabezpečeného kanálu (handshake) a přenos aplikačních dat. Během navazování si klient a server předávají informace potřebné k inicializaci šifrovacích protokolů a k autentizaci serveru pomocí certifikátu (autentizace klienta je méně běžná). Ve starších verzích protokolu TLS nebylo navazování nijak šifrováno a bylo možné jeho obsah analyzovat za účelem monitorování a zabezpečení sítě. Od verze TLS 1.3 je většina komunikace během navazování zabezpečeného kanálu šifrovaná, až na úvodní zprávu poslanou klientem ClientHello a úvodní zpráva od serveru ServerHello. ClientHello zpráva, která obsahuje důležité informace pro monitorování a vhled do TLS komunikace, bude ale v budoucnu také šifrovaná pomocí TLS rozšíření Encrypted Client Hello. Toto rozšíření je již implementované v nejpoužívanějších prohlížečích a v příštím roce lze očekávat jeho produkční nasazení. Nemožnost získávat informace přenesené během navazování TLS spojení bude mít velice negativní dopad na správu a ochranu počítačových sítí. Například již nebude možné extrahovat políčko Server Name Indication obsahující doménu cílového webového serveru. Server Name Indication je v současnosti používané ve firewallech, v IDS systémech jako je Suricata, ale i v systémech rodičovské kontroly.

Proto se v rámci projektu věnujeme zkoumání alternativních metod pro monitorování a klasifikaci TLS provozu za účelem zachování vhledu do šifrovaného provozu. Naše navrhovaná klasifikační metoda je založená na zpracování paketových sekvencí. S touto metodou jsme s velkou přesností schopni predikovat službu, s kterou uživatel v rámci TLS spojení komunikuje, a nahradit tak informace chybějící kvůli šifrování TLS ClientHello.

### Požadavek na vstupní data

Klasifikátor TLS služeb vyžaduje na vstupu síťové toky ve formátu UniRec. Síťové toky musí být obohaceny o sekvenci délek paketů, jejich směrů, časových značek a TCP příznaků. Také jsou potřeba histogramy délek paketů a mezi paketových mezer. Minimální množina informačních polí pro korektní funkcionalitu modulu je:

  

```
TIME_FIRST, TIME_LAST, BYTES, BYTES_REV, PACKETS, PACKETS_REV, TCP_FLAGS, TCP_FLAGS_REV, PPI_PKT_TIMES, PPI_PKT_DIRECTIONS, PPI_PKT_LENGTHS, PPI_PKT_FLAGS, S_PHISTS_SIZES, D_PHISTS_SIZES, S_PHISTS_IPT, D_PHISTS_IPT, FLOW_END_REASON
```

####  Architektura modulu

Modul je implementován v jazyce Python a skládá se z těchto hlavních částí:

-   Knihovna DataZoo poskytující trénovací datové sady a funkce pro předzpracování dat.
-   Definice klasifikátoru, kterým je buď neuronová síť, nebo LightGBM model založený na rozhodovacích stromech.
-   Konkrétní váhy neuronové sítě, která byla natrénovaná na datové sadě z knihovny DataZoo. Případně uložený natrénovaný LightGBM model.
    

Klasifikátor TLS služeb zpracovává jednotlivé síťové toky. Z každého toku si vybere potřebná políčka a provede předzpracování vstupních dat pomocí knihovny DataZoo. Následně se provede predikce služby pomocí klasifikačního modelu. Natrénované modely jsou součástí výstupu V3. Knihovna DataZoo hraje důležitou roli, protože poskytuje trénovací datové sady, které byly použity k trénování klasifikačních modelů, a zároveň obsahuje funkce pro předzpracování vstupních dat jako je například standardizace paketových velikostí a normalizace histogramů. Použití této knihovny zajišťuje, že vstupní data jsou předzpracovaná stejným způsobem pro trénovaní klasifikačních modelu a pro jejich použití na živém provozu.

#### DataZoo knihovna

Cílem DataZoo knihovny je podpořit vývoj modelů pro klasifikaci šifrovaného provozu. Knihovna obsahuje tři datové sady vytvořené a zveřejněné v rámci projektu – CESNET-TLS22, CESNET-QUIC22 a CESNET-TLS-Year22. Pro trénování klasifikátoru TLS služeb byla použita datová sada CESNET-TLS-Year22, která obsahuje provoz zachycený v síti CESNET3 v průběhu celého roku 2022. Dlouhá doba záchytu umožňuje trénovat a optimalizovat klasifikační modely tak, aby byly připravené na charakteristiky produkčního provozu, u kterého zároveň dochází k velkým změnám v průběhu času.

#### Architektura neuronové sítě

Pro klasifikace TLS služeb jsme vyhodnotili dvě metody - LightGBM a neuronové sítě. LightGBM je model založený na množině rozhodovacích stromů a je považovaný za jedno ze state-of-the-art řešení. U LighGBM modelů není nutné navrhovat samotnou architekturu. Je ale potřeba optimalizovat velké množství parametrů pro zajištění vysoké klasifikační přesnosti. U neuronových sítí je naopak stěžejní výběr samotné architektury. Nejlepších výsledků jsme dosáhli pomocí neuronové sítě. Tato síť používá 1D konvoluční vrstvy pro zpracování sekvencí paketových informací a lineární vrstvy pro zpracování ostatních charakteristik (na Obrázku 5 flow statistics) jako je například časová délka síťového toku, počet přenesených paketů nebo přítomnost TCP příznaků. Uprostřed sítě dochází ke spojení informací pro vytvoření takzvaného “embeddingu”–reprezentace síťového toku pomocí číselného vektoru fixní délky. Poslední část neuronové sítě má za úkol na základě embeddingu predikovat TLS službu.

### Výstup modulu

Výstup klasifikátoru se skládá z původně přijatých informací obohacených o štítek predikované TLS služby. Klasifikátor dokáže rozpoznávat dohromady 174 služeb, 50 z těchto služeb je zobrazeno v následující Tabulce.

|                          |                       |                       |
| ------------------------ | --------------------- | --------------------- |
| google-ads               | microsoft-defender    | facebook-media        |
| office365                | rubiconproject        | seznam-ssp            |
| tiktok                   | mcafee-gti            | google-conncheck      |
| microsoft-diagnostic     | doh                   | apple-location        |
| microsoft-update         | instagram             | dropbox               |
| outlook                  | skype                 | google-fonts          |
| teams                    | google-safebrowsing   | seznam-email          |
| google-www               | maps-cz               | facebook-messenger    |
| microsoft-settings       | seznam-authentication | google-services       |
| microsoft-authentication | bing                  | avast                 |
| appnexus                 | apple-itunes          | google-authentication |
| seznam-media             | twitter               | facebook-web          |
| google-play              | pubmatic              | autodesk              |
| snapchat                 | grammarly             | eset-edtd             |
| facebook-graph           | microsoft-onedrive    | unity-games           |
| youtube                  | microsoft-push        | apple-updates         |
| spotify                  | o2tv                  |                       |

### Testování

Validace klasifikátoru proběhla na vzorku produkčních datech sítě CESNET3. Pro testování jsme použili pouze síťové toky patřící službám, na kterých byl klasifikátor natrénován. Součástí modulu tedy není detekce neznámého provozu (v literatuře out-of-distribution detection). Implementace této funkcionality je plánováno v následujícím roce. Klasifikátor fungoval korektně s přesnosti 92,5% (accuracy score). Pro použití klasifikátoru založeného na neuronových sítí je zapotřebí kolektor vybavený grafickou kartou.


## Klasifikace QUIC služeb

QUIC je nový transportní protokol používaný pro přenos HTTP/3. Interně je v rámci QUIC využito protokolu TLS 1.3 pro šifrování dat a autentizaci komunikůjících stran. Motivace pro zkoumání klasifikačních metod pro protokol QUIC je tedy stejná jako pro TLS – v budoucnu lze očekávat omezení dostupných informací pro monitorování kvůli rozšíření Encrypted Client Hello (viz sekce Klasifikace TLS služeb). Oproti TLS je ale QUIC již nyní více chráněn proti jakékoliv analýze, a proto i v současnosti, bez použití Encrypted Client Hello, je obtížné získat jakékoliv informace z úvodních zpráv potřebných pro navázání šifrovaného spojení. O to důležitější jsou klasifikační metody založené na zpracování paketových sekvencí.

### Požadavek na vstupní data

Klasifikátor QUIC služeb vyžaduje na vstupu síťové toky ve formátu UniRec. Síťové toky musí být obohaceny o sekvenci délek paketů, jejich směrů a časových značek. Také jsou potřeba histogramy délek paketů a mezi paketových mezer. Minimální množina informačních polí pro korektní funkcionalitu modulu je:

  
```
TIME_FIRST, TIME_LAST, BYTES, BYTES_REV, PACKETS, PACKETS_REV, PPI_PKT_TIMES, PPI_PKT_DIRECTIONS, PPI_PKT_LENGTHS, S_PHISTS_SIZES, D_PHISTS_SIZES, S_PHISTS_IPT, D_PHISTS_IPT, FLOW_END_REASON
```

### Architektura modulu

Architekturu klasifikátoru QUIC služeb je totožná jako u klasifikátoru TLS služeb. Rozdíl je v použité trénovací datové sadě a ve velikosti neuronové sítě (architektura sítě je ale totožná).

Modul je tedy implementován v jazyce Python a skládá se z těchto hlavních částí:
-   Knihovna DataZoo poskytující trénovací datové sady a funkce pro předzpracování dat.
-   Definice klasifikátoru, kterým je buď neuronová síť, nebo LightGBM model založený na rozhodovacích stromech.
-   Konkrétní váhy neuronové sítě, která byla natrénovaná na datové sadě z knihovny DataZoo. Případně uložený natrénovaný LightGBM model.
    

K trénování klasifikátorů QUIC služeb byla použita datová sada CESNET-QUIC22 obsahující měsíc provozu ze sítě CESNET3.

### Výstup modulu

Výstup klasifikátoru se skládá z původně přijatých informací obohacených o štítek predikované QUIC služby. Klasifikátor umožňuje rozpoznat dohromady 102 služeb, 50 z těchto služeb je zobrazeno v následující Tabulce.
|                     |                       |                  |
| ------------------- | --------------------- | ---------------- |
| google-www          | google-authentication | google-drive     |
| google-services     | microsoft-outlook     | facebook-rupload |
| google-ads          | connectad             | onesignal        |
| instagram           | facebook-connect      | whatsapp         |
| google-play         | apple-privaterelay    | playradio        |
| google-gstatic      | google-autofill       | google-pay       |
| youtube             | jsdelivr              | tiktok           |
| facebook-media      | google-translate      | garmin           |
| facebook-graph      | openx                 | sme-sk           |
| google-fonts        | cloudflare-cdnjs      | google-photos    |
| snapchat            | google-calendar       | alza-www         |
| spotify             | google-docs           | alza-webapi      |
| facebook-web        | facebook-messenger    | joinhoney        |
| google-safebrowsing | fontawesome           | usercentrics     |
| discord             | google-imasdk         | google-recaptcha |
| dns-doh             | microsoft-substrate   | chess-com        |
| google-usercontent  | facebook-gamesgraph   |                  |
### Testování

Validace klasifikátoru proběhla na vzorku produkčních dat ze sítě CESNET3. Pro testování jsme použili pouze síťové toky patřící službám, na kterých byl klasifikátor natrénován. Součástí modulu tedy není detekce neznámého provozu (v literatuře out-of-distribution detection), která bude dodána v příštím roce. Klasifikátor fungoval korektně s přesnosti 90% (accuracy score). Pro použití klasifikátoru založeného na neuronových sítí je zapotřebí kolektor vybavený grafickou kartou.
