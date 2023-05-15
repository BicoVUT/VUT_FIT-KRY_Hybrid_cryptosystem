<a name="br1"></a>Dokumenta´cia

K RY: Hybridne´ sˇifrovanie

Filip Brna, xbrnaf00, 221923

24\. apr´ıla 2023




<a name="br2"></a>1 Hybridne´ sˇifrovanie

Hybridne´ sˇifrovanie, alebo hybridny´ sˇifrovac´ı syste´m, je kryptograﬁcka´ technika, ktora´ kombinuje asymetricke´ a symetricke´ sˇifry.

` `Asymetricke´ sˇifry umozˇnˇuju´ pouzˇitie roˆznych kl’u´ cˇov na sˇifrovanie a desˇifrovanie, cˇo znamena´, zˇe odosielatel’ a prij´ımatel’ nemusia zdiel’at’ zˇiadne tajomstvo vopred. Toto vsˇak moˆzˇe mat’ za na´sledoknizˇsˇiu ry´chlost’, pretozˇe asymetricke´ sˇifry vyzˇaduju´ zlozˇitejsˇie matematicke´ vy´pocˇty. Naopak symet- ricke´ sˇifry s u´ ry´chlejsˇie.

` `Hybridny´ syste´m kombinuje vy´hody oboch pr´ıstupov ty´m, zˇe najprv na´hodne vygeneruje kl’u´ cˇpre symetricku´ sˇifru a zasˇifruje n´ım spra´vu. Potom samotny´ kl’u´ cˇ zasˇifruje asymetricky a spolu sozasˇifrovanou spra´vou ho posˇle prij´ımatel’ovi. Prij´ımatel’ potom asymetrickou sˇifrou desˇifruje kl’u´ cˇa na´sledne pomocou kl’u´ cˇa pre symetricku´ sˇifru desˇifruje aj samotnu´ spra´vu. Ty´mto spoˆsobom je pomocou pomalsˇej asymetrickej sˇifry sˇifrovany´ len kra´tky kl’u´ cˇ, zatial’ cˇo samotna´ spra´va, ktora´ moˆzˇe byt’ vel’mi dlha´, je sˇifrovana´ ry´chlejsˇou symetrickou sˇifrou. Bezpecˇnost’ tohto syste´mu je za´visla´ na bezpecˇnosti oboch pouzˇity´ch sˇiﬁer. V projekte boli vyuzˇite´ algoritmy AES 128 bit, RSA 2048 a MD5 hash.

` `AES 128 bitov je sˇtandardna´ symetricka´ blokova´ sˇifra, ktora´ pouzˇ´ıva 128-bitove´ kl’u´ cˇe na sˇifrovanie a desˇifrovanie da´t. Je to vel’mi ry´chla a bezpecˇna´ sˇifra, ktora´ sa cˇasto pouzˇ´ıva na zabezpecˇenie da´t vovy´pocˇtovy´ch syste´moch a komunikacˇny´ch kana´loch. 128-bitovy´ kl’u´ cˇ poskytuje 2128 mozˇnost´ı, cˇo je obrovske´ mnozˇstvo roˆznych kl’u´ cˇov, ktore´ by bolo potrebne´ prehl’adat’ pri bruteforce (hrubou silou) u´toku. Z prakticke´ho hl’adiska je tento pocˇet tak obrovsky´, zˇe by bolo vel’mi nepravdepodobne´, zˇe by u´ tocˇn´ık doka´zal u´spesˇne prelomit’ AES s 128-bitovy´m kl’u´ cˇom.

` `RSA 2048 je asymetricka´ sˇifra, cˇasto pouzˇ´ıvana´ v hybridnom sˇifrovacom syste´me. V hybrid-nom sˇifrovan´ı sa RSA vyuzˇ´ıva na zabezpecˇenu´ vy´menu symetricke´ho kl’u´ cˇa medzi odesielatel’om a prij´ımatel’om. RSA sˇifra sa pouzˇ´ıva na vy´menu symetricke´ho kl’u´ cˇa, ktory´ sa potom pouzˇ´ıva na ry´chle a efekt´ıvne sˇifrovanie a desˇifrovanie da´t. RSA s 2048-bitovy´m kl’u´ cˇom je povazˇovany´ za bezpecˇny´ pre sˇifrovanie da´t na su´cˇasnom hardve´rovom a softve´rovom vybaven´ı. 2048-bitovy´ kl’u´ cˇ poskytuje vysoku´ u´rovenˇ bezpecˇnosti, ktora´ je dostacˇuju´ca pre va¨cˇsˇinu aplika´ci´ı. Pre RSA existuju´ aj roˆzne meto´dy u´tokov, napr´ıklad faktoriza´cia, ktora´ sa snazˇ´ı na´jst’ prvocˇ´ısla pouzˇite´ na vytvorenie kl’u´ cˇa. Avsˇak pri d´lzˇke kl’u´ cˇa 2048 bitov je tento proces vel’mi cˇasovo na´rocˇny´ a na su´cˇasnom hardve´rovom vybaven´ı by bol prakticky nemozˇny´.

` `MD5 je hashovac´ı algoritmus, ktory´ sa mozˇe pouzˇ´ıvat’ na vytvorenie jednosmerne´ho odtlacˇku (hashu) z da´t, cˇo umozˇnˇuje jednoduchu´ a ry´chlu kontrolu integrity. V hybridnom sˇifrovan´ı sa MD5moˆzˇe pouzˇit’ na ry´chlu kontrolu integrity symetricke´ho kl’u´ cˇa alebo spra´vy, ktore´ sa vymienˇaju´ medzi odesielatel’om a prij´ımatel’om.

1




<a name="br3"></a>2 Implementa´cia hybridne´ho sˇifrovania

` `Program ./kry je naimplementovany´ v programovaciom jazyku Python je mozˇne´ ho spustit’ po- stupny´mi pr´ıkazmi make build[1](#br3), na´sledne make run[2](#br3). Ide o architektu´ru klient-server na localhoste, ktora´ umozˇn´ı posielat’ spra´vy zasˇifrovane´ pomocou vysˇsˇie spomenuty´ch algorimov. Vsˇetky potrebne´ kl’u´ cˇe odosielatel’a aj pr´ıjemcu pre RSA algoritmus su´ ulozˇene´ v zlozˇke cert, v pr´ıpade, zˇe zlozˇka neexistuje, bude vytvorena´ po spusten´ı programu a taktiezˇ do nej budu´ vygenerovane´ su´kromne aj verejne´ kl’u´ cˇe odosielatel’a a pr´ıjemcu. Klu´ cˇ pre symetricke´ sˇifrovanie je na´hodne vygenerovany´ch16B po spusten´ı klienta.

` `Kl’u´ cˇe su´ vyuzˇ´ıvane´ tak, ako je to mozˇne´ vidiet’ na nasleduju´cej she´me, paket okrem spom´ınany´chda´t obsahuje aj inicializacˇny´ vektor, potrebny´ pre AES desˇifrovanie s mo´dom EAX:

Obra´zok cˇ.1 : popisuje sche´mu odosielania spra´vy, obra´zok bol prevzaty´ zo zadania projektu, ktore´ho autorom je Ing. Daniel Sna´sˇel.

` `Vy´mena symetricke´ho kl’u´ cˇa je zabezpecˇena´ rovnako ako je zobrazene´ na sche´me vysˇsˇie, ve- rejne´ kl’u´ cˇe odosielatel’a a pr´ıjemcu s u´ vol’ne dohl’adatel’ne´ napr. na internete a odosielatel’ spolu spr´ıjemcom vlastnia jedine ko´pie svojich su´kromny´ch kl’u´ cˇov, ich vy´mena nebola potrebna´. Z odosiela-nej spra´vy je najprv vygenerovany´ jej MD5 hash(16B), ktory´ je na´sledne doplneny´ o na´hodny´ch 240B a pomocou Asymetricke´ho sˇifrovania a su´kromny´m kl’u´ cˇom odosielatel’a vytvoreny´ podp´ısany´ MD5 hash, za´rovenˇ je vygenerovany´ kl’u´ cˇ relace, ktory´m je pomocou symetrickej sˇify AES zasˇifrovana´ spra´va spolu s podp´ısany´m MD5 hashom. Kl’u´ cˇ relace je taktiezˇ zarovnany´ na 256B a algoritmom

1make build- vytvor´ı virtualne prostredie s nazvom ”venva¨ nainsˇtaluje vsˇetky potrebne´ knihovny zo su´boru require- ments.txt

2make run- spust´ı program so zadany´mi parametrami

2




<a name="br4"></a>RSA spolu s verejny´m kl’u´ cˇom pr´ıjemcu je vytvoreny´ zasˇifrovany´ kl’u´ cˇ relace. Tieto sˇifrovane´ da´ta s u´ na´sledne spolu prena´sˇane´ k pr´ıjemcovi, ktory´ mus´ı najprv zistit’ kl’u´ cˇ relace a to asymetricky´m sˇifrovan´ım za pomoci su´kromne´ho kl’u´ cˇa pr´ıjemcu. Z´ıskane´mu kl’u´ cˇu relace je odstra´nene´ zarova- nie(240B) a na´sledne je n´ım symetricky desˇifrovana´ samotna´ spra´va a podp´ısany´ MD5 hash spra´vy, tento hash je z´ıskany´ pomocou RSA a verejne´ho kl’u´ cˇa odosielatel’a. Nakoniec je vygenerovany´ MD5 hash zo z´ıskanej spra´vy a porovnany´ s hashom z´ıskany´m pomocou RSA(hash m a´ taktiezˇ odstra´nene´ zarovanie) v pr´ıpade, zˇe sa zhoduju´, nedosˇlo k narusˇeniu integrity spra´vy, v opacˇnom pr´ıpade bola integrita porusˇena´. Server po prijat´ı spra´vy zasiela klientovi potrdzuju´cu spra´vu, v pr´ıpade, zˇe nebola integrita narusˇena´, inak zasiela spra´vu´ o narusˇen´ı integrity. V pr´ıpade porusˇenej integrity klient za- siela da´ta esˇte jeden kra´t.

pr´ıklady spustenia:

Klient

make run TYPE=c PORT=54321 Server

make run TYPE=s PORT=54321

` `Pri spusten´ı a zasielan´ı/prij´ıman´ı spra´v su´ na sˇtandardny´ vy´stup vypisovane´ vsˇetky zadan´ım pozˇadovane´informa´cie, da´ta su´ prevazˇne vypisovane´ v sˇestna´stkovej su´stave. Spra´vy je mozˇne´ vkladat’ v ne- konecˇnej smycˇke, ukoncˇenie je mozˇne´ ”zaslan´ım”pra´zdnej spra´vy.

Za´ver

Hybridne´ sˇifrovanie s vyuzˇit´ım AES so 128-bitovy´m kl’u´ cˇom a RSA 2048-bitovy´m kl’u´ cˇom je povazˇovane´ za bezpecˇny´ spoˆsob sˇifrovania da´t, ktory´ poskytuje vysoku´ u´rovenˇ ochrany pred u´tokmi. Avsˇak je vzˇdy doˆlezˇite´ zohl’adnit’ aj ine´ faktory, ako napr´ıklad spra´vne pouzˇitie sˇifrovania, bezpecˇnost’ kl’u´ cˇov a spra´vu kryptograﬁcky´ch materia´lov pre zabezpecˇenie u´plnej ochrany syste´mu.

3
