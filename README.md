﻿<a name="br1"></a>Dokumenta´cia

K RY: Hybridne´ sˇifrovanie

Filip Brna, xbrnaf00, 221923

24\. apr´ıla 2023




<a name="br2"></a>1 Hybridne´ sˇifrovanie

Hybridne´ sˇifrovanie, alebo hybridny´ sˇifrovac´ı syste´m, je kryptograﬁcka´ technika, ktora´ kombinuje

` `Asymetricke´ sˇifry umozˇnˇuju´ pouzˇitie roˆznych kl’u´ cˇov na sˇifrovanie a desˇifrovanie, cˇo znamena´,

` `Hybridny´ syste´m kombinuje vy´hody oboch pr´ıstupov ty´m, zˇe najprv na´hodne vygeneruje kl’u´ cˇ

` `AES 128 bitov je sˇtandardna´ symetricka´ blokova´ sˇifra, ktora´ pouzˇ´ıva 128-bitove´ kl’u´ cˇe na sˇifrovanie

` `RSA 2048 je asymetricka´ sˇifra, cˇasto pouzˇ´ıvana´ v hybridnom sˇifrovacom syste´me. V hybrid-

` `MD5 je hashovac´ı algoritmus, ktory´ sa mozˇe pouzˇ´ıvat’ na vytvorenie jednosmerne´ho odtlacˇku

1




<a name="br3"></a>2 Implementa´cia hybridne´ho sˇifrovania

` `Program ./kry je naimplementovany´ v programovaciom jazyku Python je mozˇne´ ho spustit’ po-

` `Kl’u´ cˇe su´ vyuzˇ´ıvane´ tak, ako je to mozˇne´ vidiet’ na nasleduju´cej she´me, paket okrem spom´ınany´ch

Obra´zok cˇ.1 : popisuje sche´mu odosielania spra´vy, obra´zok bol prevzaty´ zo zadania projektu, ktore´ho

` `Vy´mena symetricke´ho kl’u´ cˇa je zabezpecˇena´ rovnako ako je zobrazene´ na sche´me vysˇsˇie, ve-

1make build- vytvor´ı virtualne prostredie s nazvom ”venva¨ nainsˇtaluje vsˇetky potrebne´ knihovny zo su´boru require- ments.txt

2make run- spust´ı program so zadany´mi parametrami

2




<a name="br4"></a>RSA spolu s verejny´m kl’u´ cˇom pr´ıjemcu je vytvoreny´ zasˇifrovany´ kl’u´ cˇ relace. Tieto sˇifrovane´ da´ta

pr´ıklady spustenia:

Klient

make run TYPE=c PORT=54321 Server

make run TYPE=s PORT=54321

` `Pri spusten´ı a zasielan´ı/prij´ıman´ı spra´v su´ na sˇtandardny´ vy´stup vypisovane´ vsˇetky zadan´ım pozˇadovane´

Za´ver

Hybridne´ sˇifrovanie s vyuzˇit´ım AES so 128-bitovy´m kl’u´ cˇom a RSA 2048-bitovy´m kl’u´ cˇom je povazˇovane´

3