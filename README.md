Projekt: Hybridné šifrovanie, alebo hybridný šifrovací systém, je kryptografická technika, ktorá kombinuje asymetrické a symetrické šifry.

Asymetrické šifry umožňujú použitie rôznych kľúčov na šifrovanie a dešifrovanie, čo znamená, že odosielateľ a prijímateľ nemusia zdieľať žiadne tajomstvo vopred. Toto však môže mať za následok nižšiu rýchlosť, pretože asymetrické šifry vyžadujú zložitejšie matematické výpočty. Naopak symetrické šifry sú rýchlejšie.

Hybridný systém kombinuje výhody oboch prístupov tým, že najprv náhodne vygeneruje kľúč pre symetrickú šifru a zašifruje ním správu. Potom samotný kľúč zašifruje asymetricky a spolu so zašifrovanou správou ho pošle prijímateľovi. Prijímateľ potom asymetrickou šifrou dešifruje kľúč a následne pomocou kľúča pre symetrickú šifru dešifruje aj samotnú správu. Týmto spôsobom je pomocou pomalšej asymetrickej šifry šifrovaný len krátky kľúč, zatiaľ čo samotná správa, ktorá môže byť veľmi dlhá, je šifrovaná rýchlejšou symetrickou šifrou. Bezpečnosť tohto systému závisí na bezpečnosti oboch použitých šifrov. V projekte boli využité algoritmy AES 128 bit, RSA 2048 a MD5 hash.

make build

Klient

make run TYPE=c PORT=54321

Server

make run TYPE=s PORT=54321

Pri stupstení a zasielaní/prijímaní správ sú na štandardný výstup vypisované všetky potrebné informácie. Správy je možné vkladač v nekonečnej smyčke, ukončebnie je možné zaslaním prázdnej správy.
