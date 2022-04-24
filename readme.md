# IPK – 2. Projekt
## Autor - Tomáš Zaviačič (xzavia00)
## Funkce vytvořené aplikace
Aplikace po přeložení a spuštění zachytává ethernetové pakety ze zadaného zařízení. Podle vstupních přepínačů se vytvoří filtr pro zachycení pouze požadovaných paketů, u kterých se následně vypíšou informace:
* timestamp: čas
* src MAC: MAC adresa s : jako oddělovačem
* dst MAC: MAC adresa s : jako oddělovačem
* frame length: délka
* src IP: pokud je tak IP adresa (podpora v4 ale i v6 dle RFC5952)
* dst IP: pokud je tak IP adresa (podpora v4 ale i v6 dle RFC5952)
* src port: pokud je tak portové číslo
* dst port: pokud je tak portové číslo

## Přeložení aplikace

Součástí aplikace je obslužný program Makefile, který soubor přeloží a vytvoří spustitelný soubor s názvem „ipk-sniffer“.

## Použití aplikace

Při spouštění aplikace voláme program ve tvaru:
```bash 
./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
```
kde
* -i eth0 nebo --interface eth0 (právě jedno rozhraní, na kterém se bude poslouchat. Nebude-li tento parametr uveden, či bude-li uvedené jen -i bez hodnoty, vypíše se seznam aktivních rozhraní)
* -p 23 (bude filtrování paketů na daném rozhraní podle portu. Nebude-li tento parametr uveden, uvažují se všechny porty. Pokud je parametr uveden, může se daný port vyskytnout jak v source, tak v destination části)
* -t nebo --tcp (bude zobrazovat pouze TCP pakety)
* -u nebo --udp (bude zobrazovat pouze UDP pakety)
* --icmp (bude zobrazovat pouze ICMPv4 a ICMPv6 pakety)
* --arp (bude zobrazovat pouze ARP rámce)
* -n 10 (určuje počet paketů, které se mají zobrazit, tj. i "dobu" běhu programu. Pokud není uvedeno, aplikace uvažuje zobrazení pouze jednoho paketu)

Argumenty mohou být v libovolném pořadí a pokud nebudou konkrétní protokoly specifikovány, uvažují se k tisknutí všechny (tj. veškerý obsah, nehledě na protokol). Pokud se program ukončí zkratkou CTRL+C, program tuto událost zachytí a uvolní držené zdroje.

---
**POZOR**

Aplikace kontroluje u vloženého portu správnost jeho syntaxe a rozmezí, ve kterém se hodnota portu může pohybovat. Také u určitých přepínačů je potřeba uvést argument (např. u -p nebo -n).

---


## Ukázkové příklady zobrazení dostupných rozhraní

```
./ipk-sniffer -i
```
```
./ipk-sniffer -p 8080 -n 10 -t -u --icmp --arp -i
```

---
**POZOR**

Je nutné mít při spuštění aplikace dostatečné oprávnění.

---

## Ukázkové příklady filtrování různých paketů

```
./ipk-sniffer -i wlp4s0
```
```
./ipk-sniffer -i wlp4s0 -p 8080 -n 10 -t -u
```
```
./ipk-sniffer -p 8080 -n 10 -t -u --icmp --arp -i wlp4s0
```