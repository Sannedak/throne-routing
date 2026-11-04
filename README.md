# Throne Android: RoscomVPN + Mobile Whitelist

[![Build and publish routing](https://github.com/Sannedak/throne-routing/actions/workflows/build.yml/badge.svg)](https://github.com/Sannedak/throne-routing/actions/workflows/build.yml)

Ежедневная сборка совместимых правил из [RoscomVPN Routing](https://github.com/hydraponique/roscomvpn-routing) и [Russia Mobile Internet Whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) для Throne Android 2.x.

**Это перенос правил маршрутизации, а не полной конфигурации Happ, INCY или Mihomo.** Сервер VPN, подписка, DNS и параметры транспорта настраиваются отдельно. `.srs` содержит условия совпадения; действия и их приоритет задаёт профиль маршрутизации.

## Что импортировать

| Профиль | Поведение | Постоянный HTTPS URL |
|---|---|---|
| `roscom-mobile` | RoscomVPN DEFAULT + точные домены и IP из Hxehex в DIRECT после исключений BLOCK/PROXY | [JSON](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-mobile.route.json) · [ссылка импорта](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-mobile.import.txt) |
| `roscom-default` | Совместимые правила исходного HAPP/DEFAULT.JSON | [JSON](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-default.route.json) · [ссылка импорта](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-default.import.txt) |
| `roscom-whitelist` | Совместимые правила исходного HAPP/WHITELIST.JSON; это whitelist RoscomVPN, не Hxehex | [JSON](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-whitelist.route.json) · [ссылка импорта](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-whitelist.import.txt) |

Для поставленной задачи выбирайте `roscom-mobile`. Он расширяет DIRECT исходного DEFAULT; это **не** режим «напрямую исключительно разрешённое оператором». Все несовпавшие соединения идут через выбранный в Throne прокси.

## Импорт в Throne Android 2.x

1. Сначала добавьте и проверьте свой рабочий сервер/подписку VPN.
2. Откройте [ссылку импорта roscom-mobile](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-mobile.import.txt). Скопируйте **содержимое файла целиком**: строку `throne://remoteroute/...`, а не HTTPS-адрес этого текстового файла.
3. В Throne откройте боковое меню → **Routing / Маршрутизация** → меню импорта → **Import from clipboard / Импорт из буфера**. Подтвердите добавление удалённого профиля, оставьте **Auto update** включённым.
4. Выберите `roscom-mobile` на экране маршрутизации. Само добавление не делает его активным. Если у группы серверов выбран отдельный профиль маршрутизации, назначьте `roscom-mobile` и этой группе либо верните наследование общего профиля.
5. Проверьте правила: `DNS interception`, `BLOCK sites`, `PROXY sites`, `DIRECT sites`, `Resolve after domain rules …`, `DIRECT ip`. По умолчанию должен быть выбран `proxy`. Не переставляйте DIRECT выше BLOCK/PROXY.
6. Включите обновление удалённых профилей в настройках подписок (интервал 1440 минут). После обновления профиля переподключитесь. При работающем соединении **Routing → Update rule-sets** обновляет сами `.srs`.

Альтернативный путь: **Routing → New → Remote profile**, имя `roscom-mobile`, URL [roscom-mobile.route.json](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-mobile.route.json), загрузить/сохранить и выбрать профиль. Названия кнопок зависят от языка и версии.

Формат `kind: throne-route-profile`, версия `v: 1`, строковые `proxy/direct`, действие `reject`, URL `.srs` и `throne://remoteroute/` сверены с исходниками [Throne Android v2.0.0 RouteShare](https://github.com/throneproj/ThroneForAndroid/blob/v2.0.0/app/src/main/java/io/nekohasekai/sagernet/route/RouteShare.kt) и [текущим RouteShare](https://github.com/throneproj/ThroneForAndroid/blob/6df7c03b6aa34663e4a41d90ca52a10c2fb188f0/app/src/main/java/io/nekohasekai/sagernet/route/RouteShare.kt). Это проверка формата по реализации; установка и импорт на физическом Android-устройстве отдельно не подтверждены.

Не импортируйте `.srs` как подписку серверов или raw sing-box JSON. Android не поддерживает raw routing profiles; используйте подготовленный структурированный профиль. См. [документацию Android](https://throneproj.github.io/android/) и [маршрутизации](https://throneproj.github.io/guides/routing/).

## Приоритеты и границы переноса

Профили выполняют доменные правила **BLOCK → PROXY → DIRECT**, затем разрешают ещё не обработанное доменное имя и проверяют IP-правила в том же порядке; остаток — PROXY. В текущих исходниках списки BlockIp и ProxyIp пусты. Это воспроизводит совместимую часть `IPIfNonMatch`: сначала доменное совпадение, затем IP. Полная эквивалентность Xray/Happ не заявляется: в Android доступность имени/IP зависит от DNS, FakeIP и sniffing. Для неизвестного имени с уже известным IP результат может зависеть от поведения ядра.

| Исходное условие | Преобразование |
|---|---|
| GeoSite `domain:` или строка без префикса | `domain_suffix` — домен и его поддомены |
| `full:` | `domain` — точное имя |
| `keyword:` | `domain_keyword` |
| `regexp:` | `domain_regex`, без изменения регистра выражения |
| GeoIP | Проверенные IPv4/IPv6 CIDR; сохранены исходные исключения RoscomVPN |
| Hxehex `whitelist.txt` | Точное имя SNI, без расширения на все поддомены |
| Hxehex `ipwhitelist.txt` + `cidrwhitelist.txt` | Объединение отдельных адресов и сетей, точная свёртка CIDR |

В отличие от повторного использования готового upstream `.srs`, GeoSite собирается из исходных `data/` с семантикой [domain-list-community](https://github.com/v2fly/domain-list-community#structure-of-data). Это существенно для строк без префикса: они означают суффикс, а не произвольную подстроку. Будущие неизвестные конструкции, включая `include:` и селекторы категорий, останавливают сборку вместо пропуска правил.

Не перенесены автоматически:

- DNS-серверы и транспорт DoH исходника; `DnsHosts` для `lkfl2.nalog.ru` и `lknpd.nalog.ru`.
- Специфичные параметры Happ/INCY (`UseChunkFiles`, импорт geo-баз), настройки Mihomo, серверы и proxy-groups.
- Общая блокировка протокола BitTorrent: источник блокирует список известных DHT-доменов, это не блокировка всех торрентов.
- Доступность VPN во время ограничений мобильной сети. Список Hxehex — наблюдения разных операторов/регионов, не гарантия доступности и не способ сделать недоступный сервер достижимым.

Настройки DNS остаются вашими. В исходном RoscomVPN указаны remote DoH `https://8.8.8.8/dns-query` и direct DoH `https://77.88.8.8/dns-query`; при необходимости задайте их в Throne вручную. Автоматический DNS routing Throne распознаёт встроенные имена `geosite-*`, но не обязан выводить DNS-политику из наших произвольных URL `.srs`. Поэтому разделение DNS RoscomVPN **не считается перенесённым**. Не включайте TUN bypass/direct-IP обход ядра: он может обойти приоритетные правила. Дополнительный AdBlock Throne добавляет собственные блокировки сверх этого профиля.

При первом подключении нужны доступные GitHub/raw.githubusercontent.com либо уже загруженный кэш. Если Throne предлагает подключиться без rule-sets, такие правила временно не действуют. Для проверки полного набора дождитесь загрузки всех файлов; удобнее первый импорт выполнить через работающую сеть/Wi-Fi.

## Сборка и публикация

Workflow запускается ежедневно в **03:17 UTC / 09:17 Омск**, вручную через Actions → Build and publish routing → Run workflow и при изменении исходников в `main`. Cron GitHub может задерживаться; при длительном отсутствии активности публичного репозитория GitHub может отключить расписание — его нужно снова включить на странице Actions.

Каждая сборка:

1. Фиксирует SHA коммита RoscomVPN Routing и Hxehex. Для GeoSite/GeoIP берёт именно версии из `Geositeurl`/`Geoipurl` этого снимка, затем фиксирует их SHA.
2. Строго разбирает источники. Некорректный IP, пустой файл, неизвестное поле маршрутизации или новая семантика источника прерывают сборку.
3. Компилирует SRS v3 закреплённым sing-box **1.12.12**, проверенным по SHA-256; декомпилирует каждый бинарный файл и выполняет `sing-box check` для всех профилей с тестовым proxy outbound.
4. Одним коммитом публикует результат в ветку `rules`, сохраняя предыдущие коммиты. Сборка с ошибкой до публикации не заменяет действующие файлы.
5. Скачивает опубликованные файлы по публичным HTTPS-адресам и сверяет SHA-256. Только после этого запуск считается успешным. Ошибка после push может означать, что публикация есть, но внешняя проверка не завершилась — смотрите шаги запуска.

Постоянная база ссылок: `https://raw.githubusercontent.com/Sannedak/throne-routing/rules/`.

Основные наборы: [BLOCK](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-default-block-sites.srs), [PROXY](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-default-proxy-sites.srs), [DIRECT domains](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-default-direct-sites.srs), [DIRECT IP](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/roscom-default-direct-ip.srs), [Mobile domains](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/mobile-domains.srs), [Mobile IP](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/mobile-ips.srs).

[Манифест источников и счётчиков](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/manifest.json) · [SHA256SUMS](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/SHA256SUMS) · [История сборок](https://github.com/Sannedak/throne-routing/actions/workflows/build.yml).

Чтобы повторить сборку локально с установленным sing-box: `python3 -m unittest -v`, затем `python3 build.py --output dist`. Каталог `dist` должен быть новым/пустым; `.source-cache` фиксирует скачанные ответы текущей проверки, для свежей сборки укажите новый `--cache`.

После импорта проверьте в журнале/дашборде Throne: GitHub/YouTube → proxy, домен из BLOCK → reject, известный российский домен из DIRECT → direct. Проверка синтаксиса и сборки не доказывает доступность сервисов у вашего оператора.

Исходные данные сохраняют условия своих авторов; уведомления и доступные лицензии публикуются рядом с результатом. Репозиторий не приписывает себе авторство или единую лицензию сторонних баз.
