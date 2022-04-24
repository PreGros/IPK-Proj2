# IPK – 2. Projekt
## Autor - Tomáš Zaviačič (xzavia00)
## Funkce vytvořené aplikace
Po přeložení skriptu SocketProgram.CPP se vytvoří spustitelný soubor. Server po spuštění naslouchá na určitém portu. Pokud přijde url ve správném tvaru, vrací odpověď podle typu url. Pokud bude url ve špatném tvaru, vrací zprávu „BAD request“ s chybným kódem 400. Správné url jsou:
* hostname – vrací síťové jméno počítače včetně domény
* cpu-name – vrací jméno procesoru, na kterém je server spuštěný
* load – vrací aktuální informace o zátěži procesoru

## Přeložení aplikace

Součástí aplikace je obslužný program Makefile, který soubor přeloží a vytvoří spustitelný soubor s názvem „hinfosvc“.

## Použití aplikace

Při spuštění se port, na kterém server naslouchá, nastaví automaticky na 8080. Pokud nechceme používat tento základní port, můžeme ho prvním argumentem při spuštění změnit. Syntaxe je následující:

```bash 
./hinfosvc <PORT>
```
---
**POZOR**

Aplikace kontroluje u vloženého portu správnost jeho syntaxe a rozmezí, ve kterém se hodnota portu může pohybovat. 

---
Aplikace tedy přijímá žádný nebo právě jeden argument. Jakýkoliv jiný počet argumentů je předpokládáno za chybu. Server lze vypnout zkratkou CTRL+C. 

## Ukázkové příklady spuštění serveru

```
./hinfosvc
```
```
./hinfosvc 8090
```

## Ukázkové příklady připojení na server

```
GET http://localhost:8080/hostname
```
```
GET http://localhost:8080/cpu-name
```
```
GET http://localhost:8080/load
```