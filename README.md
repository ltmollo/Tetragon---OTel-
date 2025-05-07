# Dokumentacja projektu

---

## Tytuł: Tetragon-OTel

**Autorzy:**  
- Dawid Kardacz  
- Michał Kuszewski  
- Adrian Madej  
- Adrian Mrzygłód  

**Grupa:** 5  
**Rok:** 2025  

---

## Spis treści

1. [Wprowadzenie](#1-wprowadzenie)  
2. [Podstawy teoretyczne i stos technologiczny](#2-podstawy-teoretyczne-i-stos-technologiczny)  
3. [Opis koncepcji studium przypadku](#3-opis-koncepcji-studium-przypadku)  
4. [Architektura rozwiązania](#4-architektura-rozwiązania)  
5. [Opis konfiguracji środowiska](#5-opis-konfiguracji-środowiska)  
6. [Metoda instalacji](#6-metoda-instalacji)  
7. [Jak odtworzyć projekt – krok po kroku](#7-jak-odtworzyć-projekt--krok-po-kroku)  
   - [Podejście Infrastructure as Code](#71-podejście-infrastructure-as-code)  
8. [Kroki wdrożenia demonstracyjnego](#8-kroki-wdrożenia-demonstracyjnego)  
   - [Konfiguracja środowiska](#81-konfiguracja-środowiska)  
   - [Przygotowanie danych](#82-przygotowanie-danych)  
   - [Procedura wykonawcza](#83-procedura-wykonawcza)  
   - [Prezentacja wyników](#84-prezentacja-wyników)  
9. [Wykorzystanie AI w projekcie](#9-wykorzystanie-ai-w-projekcie)  
10. [Podsumowanie – wnioski](#10-podsumowanie--wnioski)  
11. [Bibliografia / Referencje](#11-bibliografia--referencje)  

---

## 1. Wprowadzenie

W projekcie opracowana została aplikacja funkcjonująca w środowisku Kubernetes, z naciskiem na integrację z systemem monitoringu i obserwowalności zgodnym ze standardem OpenTelemetry. Kluczową rolę pełni tutaj narzędzie **Tetragon**, wykorzystujące technologię **eBPF**, które pozwala na skuteczne śledzenie zdarzeń zachodzących w systemie operacyjnym i egzekwowanie polityk bezpieczeństwa bezpośrednio na poziomie jądra.

Tetragon umożliwia szczegółowe monitorowanie działań procesów, wywołań systemowych oraz operacji wejścia-wyjścia, jednocześnie uwzględniając kontekst środowiska Kubernetes, taki jak przestrzenie nazw, pody czy konkretne workloady. Dane te są zbierane w czasie rzeczywistym i przekazywane do **Grafany**, gdzie możliwa jest ich wizualizacja i dalsza analiza.

---

## 2. Podstawy teoretyczne i stos technologiczny

### 2.1 Podstawy teoretyczne

**Tetragon** to zaawansowane narzędzie służące do monitorowania bezpieczeństwa systemu oraz egzekwowania polityk w czasie rzeczywistym, zaprojektowane z myślą o nowoczesnych środowiskach chmurowych, w szczególności opartych na Kubernetes. Wykorzystuje technologię **eBPF** (extended Berkeley Packet Filter), co pozwala na wykonywanie obserwacji bezpośrednio w jądrze systemu operacyjnego bez konieczności modyfikowania aplikacji.

Główne możliwości Tetragona to:

- stosowanie reguł bezpieczeństwa i filtrów w jądrze systemu z minimalną utratą wydajności,
- natychmiastowa reakcja na wykryte zdarzenia o charakterze bezpieczeństwa,
- monitorowanie procesów i operacji systemowych w czasie rzeczywistym.

Tetragon rozpoznaje i rejestruje m.in.:

- uruchamianie procesów i ich dziedziczenie,
- wywołania systemowe (syscalls),
- dostęp do zasobów takich jak pliki czy sieć.

Dzięki świadomości kontekstu Kubernetes, Tetragon potrafi rozpoznać:

- namespace’y,
- pody,
- konkretne workloady lub kontenery.

Dzięki temu możliwe jest tworzenie bardzo precyzyjnych i kontekstowych polityk bezpieczeństwa oraz efektywne śledzenie działania aplikacji z punktu widzenia zarówno systemu operacyjnego, jak i platformy Kubernetes.

---

### 2.2 Stos technologiczny

Projekt został zrealizowany w lekkim, lokalnym środowisku testowym zbudowanym przy użyciu narzędzia **Kind (Kubernetes in Docker)**. Umożliwia ono szybkie tworzenie klastra Kubernetes w kontenerach Dockera, co jest idealnym rozwiązaniem do celów rozwojowych i testowych.

Zarządzanie wdrożeniem komponentów aplikacji oraz ich konfiguracją zostało zrealizowane za pomocą narzędzia **Helm** – menedżera pakietów dla Kubernetes. Helm pozwala na definiowanie aplikacji jako zestawu konfigurowalnych „chartów”, które można łatwo instalować, aktualizować i usuwać w klastrze.

Technologie wykorzystane w projekcie:

- **Kubernetes** – system orkiestracji kontenerów,
- **Kind** – środowisko uruchomieniowe dla lokalnego klastra Kubernetes,
- **Helm** – zarządzanie wdrożeniami i konfiguracją aplikacji,
- **Tetragon** – obserwowalność bezpieczeństwa i runtime enforcement oparty na eBPF,
- **Grafana** – wizualizacja danych telemetrycznych,
- **OpenTelemetry** – standard zbierania metryk, logów i śladów w aplikacjach rozproszonych.

---

## 3. Opis koncepcji studium przypadku

*TO DO*

---

## 4. Architektura rozwiązania

*TO DO*

---

## 5. Opis konfiguracji środowiska

*TO DO*

---

## 6. Metoda instalacji

*TO DO*

---

## 7. Jak odtworzyć projekt – krok po kroku

*TO DO*

### 7.1 Podejście Infrastructure as Code

*TO DO*

---

## 8. Kroki wdrożenia demonstracyjnego

### 8.1 Konfiguracja środowiska

*TO DO*

### 8.2 Przygotowanie danych

*TO DO*

### 8.3 Procedura wykonawcza

*TO DO*

### 8.4 Prezentacja wyników

*TO DO*

---

## 9. Wykorzystanie AI w projekcie

*TO DO*

---

## 10. Podsumowanie – wnioski

*TO DO*

---

## 11. Bibliografia / Referencje

*TO DO*

---

