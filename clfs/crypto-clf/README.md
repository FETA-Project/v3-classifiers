# Detekce těžby kryptoměn
Těžba kryptoměn typu PoW (Proof-of-Work) je proces náročný na výpočetní zdroje a tím pádem i na spotřebu elektřiny. Odměnu dostane pouze ten, kdo první “vytěží” nový blok. Při velké konkurenci (velkému počtu “minerů”) je tato šance ale velmi malá. Ten, kdo těží kryptoměny, proto ve většině případů nepracuje sám, ale připojuje se do tzv. mining poolu, což je skupina lidí, která těží kryptoměny společně a rozděluje si odměny. Ke komunikaci přitom využívají Stratum protokol. Detekce těžby kryptoměn může v jistých případech dokonce znamenat prolomení ochran a kompromitaci sítě - např. detekování těžby kryptoměn v korporátní/univerzitní síti může svědčit o zneužívání prostředků zaměstnancem nebo neznámým útočníkem. Softwarový detekční modul, zahrnutý ve výsledku V3, zvaný DeCrypto, je schopný nejen detekovat těžbu kryptoměn, ale i pracovat s velkým množstvím dat, čímž dokáže chránit stovky tisíc uživatelů najednou.

## Požadavek na vstupní data
Detektor těžby kryptoměn na vstupu vyžaduje síťové toky ve formátu UniRec. Vstupní síťové toky musí, kromě základních políček, obsahovat také informace o sekvenci prvních 30 paketů (délky paketů, časové značky, směry a TCP příznaky). Dále také políčka nazývaná IDP Content, která obsahují prvních 100 bajtů dat přenesených daným tokem. V poslední řadě také hodnota Server Name Indication protokolu TLS v případě, že tok obsahoval TLS Client Hello. Požadované vstupní informační polejsou:

```
SRC_IP, DST_IP, SRC_PORT, DST_PORT, PROTOCOL, BYTES, BYTES_REV, PACKETS, PACKETS_REV, TIME_FIRST, TIME_LAST, TCP_FLAGS, TCP_FLAGS_REV, IDP_CONTENT, IDP_CONTENT_REV, TLS_SNI, PPI_PKT_DIRECTIONS, PPI_PKT_TIMES, PPI_PKT_LENGTHS, PPI_PKT_FLAGS
```

## Architektura Modulu
Detektor těžby kryptoměn zpracovává jednotlivé síťové toky. Pro každý tok provede detekci a v případě pozitivního výsledku odesílá informace o spojení na výstupní interface. Základním prvkem tohoto detekčního modulu je Weak Indication Framework (WIF), což je knihovna, která implementuje nejčastěji používané detekční metody v oblasti klasifikace síťového provozu (detailně popsána níže).

Detektor je postaven na myšlence heterogenního ensemble modelu—skládá se z několik klasifikátorů, jejichž výstup je kombinován dohromady pro přesnější a spolehlivější detekci.

### Weak Indication Framework
Weak Indication Framework (WIF) je C++ knihovna, která cílí na usnadnění vývoje nových detekčních a klasifikačních modulů. Skládá se z několika částí, přičemž klasifikátory a kombinátory jsou nejdůležitější.

Klasifikátory jsou třídy, které implementují detekční metody. Jednotný interface zajišťuje snadné použití, případně umožňuje rychlé provádění změn (výměna klasifikační metody apod.). Pro detektor těžby kryptoměn jsou nejdůležitější dva klasifikátory—regex klasifikátor a klasifikátor provádějící detekci pomocí strojového učení (konkrétně pomocí knihovny scikit-learn).

Regex klasifikátor na vstupu dostane seznam slov, které v definovaných políčkách detekuje pomocí regulárního výrazu. Můžeme ho tedy použít pro detekci klíčových slov nebo přímo zjišťovat, zda nějaké textové políčko má definovanou strukturu.

Klasifikátor strojového učení na vstupu dostane cestu k Machine Learning modelu v pickle formátu a k tzv. mostu (angl. bridge), pomocí kterého jsou poté volány metody z Python knihovny implementující strojové učení—SciKit Learn. Bridge slouží k zajištění komunikace mezi WIF (C++ knihovna) a SciKit Learn (Python knihovna). Pro každý síťový tok poté provede predikci pomocí vstupního ML modelu, výstupem je pravděpodobnost příslušnosti síťového toku k daným třídám.

Kombinátory jsou druhá důležitá součást WIF. Umožňují kombinovat výstupy klasifikátorů dohromady, čímž zpřesňují a zvyšují kvalitu detekčních algoritmů Můžeme si tedy např. definovat dva klasifikátory—jeden bude provádět detekci pomocí regulárních výrazů (výstupem může být kolik % slov bylo detekováno), a klasifikátor strojového učení bude vracet pravděpodobnost, že tok patří do škodlivé třídy. Pomocí součtového kombinátoru můžeme získat součet, pomocí průměrového kombinátoru zase průměr. WIF dále obsahuje i tzv. binární Dempster-Shafer Theory (DST) kombinátor, který z každého vstupního prvku vytvoří basic mass probability assignment funkci, a na všechny tyto pravděpodobnostní funkce dále aplikuje Dempster’s Rule of Combination. Dostaneme tedy finální pravděpodobnostní funkci, která vše kombinuje dohromady.

### Architektura detektoru těžby kryptoměn
Detektor těžby kryptoměn je složen ze tří slabých detektorů: detektor protokolu Stratum, detektor klíčových slov v TLS SNI a detektor typu provozu založený na strojovém učení. Výstupy detektorů klíčových slov a typu provozu jsou dále kombinovány dohromady pomocí binárního DST kombinátoru. 

#### Detektor protokolu Stratum
Stratum je protokol založený na JSON RPC 2.0, pomocí kterého komunikují jednotliví těžaři (mineři) a komunita kryptoměny (často tzv. mining pool). Pokud je tato komunikace nezabezpečená, dá se z prvních 100 bajtů spolehlivě určit, zda se jedná o protokol Stratum. Tento protokol je založený na žádostech (request) a odpovědích (response). Detektor provádí detekci založenou na rozpoznávání vzorů komunikace (pattern matching), pomocí které detekuje Stratum request. Využívá regex klasifikátor z knihovny WIF, kterému předává IDP Content políčka. Tento detektor je určen pro zpracování nešifrovaného provozu.

#### Detektor klíčových slov v TLS SNI
Pokud je provoz zašifrovaný, detektor protokolu Stratum ho není schopen detekovat. Strany však šifrované TLS spojení musí navázat a klient musí poslat doménové jméno (políčko Server Name Indication v TLS Client Hello). Dřívější výzkum ukázal, že mnoho mining pool serverů ve svém doménovém jméně obsahuje klíčové slovo indikující těžbu. Dále také často obsahují zkrácené jméno kryptoměny, pro kterou jsou určeny. Příkladem jsou např. xmr.2miners.com (klíčové slovo mine, zkrácený název kryptoměny Monero - xmr). Tento detektor hledá dvě skupiny klíčových slov v SNI hodnotě—klíčová slova indikující těžení (mine, mining, pool) a zkrácené názvy kryptoměn (btc, eth, xmr, rvn). Pro minimalizaci falešně pozitivních hlášení musí krátkým jménům kryptoměn navíc předcházet nebo následovat, znak tečky,nebo pomlčky (v uvedeném příkladu doménového jména vidíme xmr.). Výstupem toho detektoru je hodnota jedna z následujících tří hodnot: 0 (doména neobsahuje žádné klíčové slovo ), 0.5 (doména obsahuje alespoň jedno slovo z pouze jedné skupiny klíčových slov), 1 (doména obsahuje alespoň jedno slovo z obou dvou skupin klíčových slov).


#### Detektor typu provozu
Poslední slabý detektor je založen na strojovém učení. Tento detektor na základě statistických vlastností provozu určuje, zda se jedná o síťový tok reprezentující provoz těžení kryptoměny, nebo ne. Vstupem je celkem 12 charakteristik (features), které jsou i vstupem do modelu strojového učení. Popisují objem přenesených dat (bajtů), objem přenesených paketů, dále popisují poměry přenesených dat od klienta na server a od serveru ke klientovi (obdobně i poměry přenesených paketů oběma směry), mezipaketové mezery, průměrnou velikost paketu a poměr paketů, které obsahovaly TCP PUSH příznak. Tyto charakteristické vlastnosti byly vybrány v rámci předchozích aktivit, stejně tak jako použitý model strojového učení, Random Forest, a jeho nastavení.

#### Meta detektor
Detektor těžby kryptoměn je složený ze tří slabých detektorů. O finální predikci se stará meta detektor, který zpracovává výstupy všech tří slabých detektorů. Detekce protokolu Stratum je velmi spolehlivá, proto se zpracovává nejdříve. Pokud je detekován Stratum protokol, je síťový tok označen jako pozitivní a rovnou odeslán na výstup. Pokud Stratum detekován nebyl, meta detektor pokračuje dále a spustí detektor typu provozu (strojové učení). Pokud je hodnota SNI prázdná, je predikce založena na porovnání s minimální potřebnou pravděpodobností pro pozitivní klasifikaci. Jinak se spustí detektor klíčových slov, jehož výstup je společně s pravděpodobností ze strojového učení zkombinován dohromady pomocí binárního DST kombinátoru. Tato finální pravděpodobnost je poté porovnána s minimální hodnotou DST pravděpodobnosti.

## Výstup modulu
Výstup detektoru těžby kryptoměn obsahuje informace o identifikaci komunikujících stran, volumetrické informace o komunikaci a hodnotu SNI. Dále rozšiřuje výstup o výsledek detekce těžby kryptoměn doplněnou o čas detekce a informaci, které části meta detektoru učinily finální rozhodnutí. Přehled polí ve výstupní UniRec zprávě je v následující Tabulce. Pokud detektor běží ve standardním módu, posílá tyto informace na výstup pouze pokud byla těžba detekována. Informace o tocích, kde těžení detekováno nebylo, se na výstup neposílá. Výstupní UniRec zprávy obsahují následující UniRec políčka:
```
SRC_IP, DST_IP, SRC_PORT, DST_PORT, PROTOCOL, BYTES, BYTES_REV, PACKETS, PACKETS_REV, TIME_FIRST, TIME_LAST, TLS_SNI, DETECT_TIME, PREDICTION, EXPLANATION
```

| Název UniRec Políčka | Hodnota          | Popis                                                                                             |
|----------------------|------------------|---------------------------------------------------------------------------------------------------|
| DETECT_TIME          | CURRENT DATETIME | Časová značka, kdy byl tok označen jako těžení kryptoměn                                          |
| PREDICTION           | 0                | Těžení kryptoměny nebylo detekováno                                                               |
|                      | 1                | Těžení kryptoměny bylo detekováno                                                                 |
| EXPLANATION          | STRATUM          | Stratum protokol byl detekován                                                                    |
|                      | DST              | Kombinace detekce podezřelá klíčových slov v SNI a typu provozu označila tok jako těžbu kryptoměn |
|                      | ML               | Pravděpodobnost z ML přesáhla minimální práh                                                      |

## Testování
Testování detektoru těžby kryptoměn proběhlo nejdříve “offline”, na zachycených dat ze sítě CESNET3 v rozmezí jednoho měsíce. Detektor na této datové sadě obsahující více než jeden milion vzorků dosáhl přesnosti 93.7%. Dále byl detektor nasazen přímo na síti CESNET3 od června 2022, kde po dobu více než 12 měsíců hlásil odhalené těžení kryptoměn. Během prvotního nasazení bylo provedeno mnoho změn a vylepšení, které zvýšily efektivitu detektoru a výrazně snížily jak počet výstupních hlášení, tak i minimalizovaly počet falešně pozitivních hlášení. Poté již byly pouze vyhodnocovány výstupy detektoru, kdy detektor dosahoval vysoké přesnosti a odhalil těžbu námi předem neznámé kryptoměny, jejíž zkrácený název byl poté zpětně zařazen do detektoru (kryptoměna RVN, viz. sekce Detektor klíčových slov v TLS SNI výše).
