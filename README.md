# Throne Android: профили по образцу Shadowrocket

[![Build and publish routing](https://github.com/Sannedak/throne-routing/actions/workflows/build.yml/badge.svg)](https://github.com/Sannedak/throne-routing/actions/workflows/build.yml)

Три профиля для Throne Android 2.x по активным правилам [misha-tgshv/shadowrocket-configuration-file](https://github.com/misha-tgshv/shadowrocket-configuration-file). Ежедневное обновление, настоящие sing-box `.srs`, сохранённый порядок правил.

**Это перенос маршрутизации, а не полной конфигурации Shadowrocket.** Сервер VPN, DNS, IPv6, исключения TUN, группы серверов, MITM и модули настраиваются отдельно. Проверка импорта по исходникам приложения не заменяет испытание на телефоне.

## Выбор профиля

| Профиль | Правила сверху вниз | Остальной трафик | Импорт |
|---|---|---|---|
| **Basic** `sr-ru-basic` | Домены сообщества → PROXY; IP сообщества → PROXY; Telegram, Discord, WhatsApp → PROXY; IP Telegram и Meta → PROXY | **DIRECT** | [Строка импорта](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/sr-ru-basic.import.txt) · [JSON](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/sr-ru-basic.route.json) |
| **Geo** `sr-ru-geo` | Исключения custom-proxy → PROXY; российские IP → DIRECT; IP-чекеры → DIRECT | **PROXY** | [Строка импорта](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/sr-ru-geo.import.txt) · [JSON](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/sr-ru-geo.route.json) |
| **Whitelist** `sr-ru-whitelist` | IP белого списка RoscomVPN → DIRECT; точные имена Hxehex → DIRECT | **PROXY** | [Строка импорта](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/sr-ru-whitelist.import.txt) · [JSON](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/sr-ru-whitelist.route.json) |

В текущих трёх исходниках нет активных BLOCK/REJECT. Старые блокировки RoscomVPN в новые профили не добавляются. Обработчик поддерживает REJECT/BLOCK как `reject` и сохраняет порядок действий: первое совпадение побеждает.

В Geo строки для суффиксов `.ru/.рф/.su` закомментированы, поэтому не включены. Описание в README автора местами отличается от активного конфига. Аналогично не включены закомментированные voice_ports, банковские и другие необязательные списки. Раздел Rule в подключаемом `sr_ru_extended.conf` сейчас пуст; появление правил в нём остановит сборку для проверки порядка включения.

## Импорт в Throne Android 2.x

1. Добавьте рабочий VPN-сервер/подписку и проверьте подключение.
2. Откройте **«Строка импорта»** нужного профиля. Скопируйте содержимое целиком: строку `throne://remoteroute/...`, а не HTTPS-адрес `.import.txt`.
3. В Throne: боковое меню → **Routing / Маршрутизация** → меню импорта → **Import from clipboard / Импорт из буфера**. Добавьте удалённый профиль с включённым **Auto update**.
4. Выберите добавленный профиль на экране маршрутизации. Сам импорт его не активирует. Если группа серверов использует свой профиль, назначьте новый и ей либо включите наследование общего.
5. Проверьте направление по умолчанию: **direct для Basic**, **proxy для Geo и Whitelist**. Сохраните порядок правил.
6. Задайте обновление удалённых профилей каждые 1440 минут. После обновления переподключитесь. **Routing → Update rule-sets** обновляет сами `.srs`; структура профиля и наборы правил обновляются отдельно.

Альтернатива: **Routing → New → Remote profile**, URL `.route.json` из таблицы, загрузить, сохранить и выбрать. Названия кнопок зависят от языка и версии.

Не импортируйте профиль маршрутизации как подписку серверов, а `.srs` — вместо профиля. Android использует структурированный формат `kind: throne-route-profile`, `v: 1`, строковые `proxy/direct`, `type: custom` и HTTPS URL `.srs`. Формат и кодирование ссылки сверены с [RouteShare v2.0.0](https://github.com/throneproj/ThroneForAndroid/blob/v2.0.0/app/src/main/java/io/nekohasekai/sagernet/route/RouteShare.kt) и [текущей реализацией](https://github.com/throneproj/ThroneForAndroid/blob/6df7c03b6aa34663e4a41d90ca52a10c2fb188f0/app/src/main/java/io/nekohasekai/sagernet/route/RouteShare.kt).

**Фактический импорт на Android-устройстве не проверен.** Проверены формат, сборка ядром и опубликованные файлы. Документация: [Android](https://throneproj.github.io/android/) · [Маршрутизация](https://throneproj.github.io/guides/routing/).

## Преобразование и ограничения

| Условие | Результат |
|---|---|
| DOMAIN | Точное имя `domain` |
| DOMAIN-SUFFIX | Домен и поддомены `domain_suffix` |
| DOMAIN-KEYWORD | Подстрока `domain_keyword` |
| IP-CIDR, голые IPv4/IPv6 | Проверенные CIDR без расширения диапазона |
| IP-ASN Telegram | Диапазоны соответствующих ASN из GeoLite2-ASN CSV, опубликованного Loyalsoldier/geoip |
| GEOIP,RU | `text/ru.txt` из той же семьи базы Loyalsoldier/geoip, что рекомендованная Country-without-asn.mmdb |
| no-resolve | Не добавляется действие разрешения имени |
| IP-правило с разрешением | `resolve` непосредственно перед первым таким правилом |
| Голые имена Hxehex | Точное имя, без расширения на поддомены |

В Basic дополнительного resolve нет: все IP-правила используют no-resolve. Уже известный IP из TUN/DNS/sniffing может совпасть. В Geo resolve стоит после custom-proxy и перед GeoIP, в Whitelist — перед IP-списком. Доступность имени/IP зависит от клиента; полная эквивалентность сетевого поведения Shadowrocket не заявляется.

Конфиги сохранены как `source-sr-ru-*.conf`. В разделе `shadowrocket` [манифеста](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/manifest.json) указаны точные коммиты, исходные правила, счётчики и число диапазонов каждого ASN. ASN без текущих диапазонов отмечается числом 0. Файлы zkeen скачиваются из конкретного релиза с проверкой SHA-256 GitHub Release.

Отдельно учитывайте:

- **DNS:** Basic/Geo в образце используют Cloudflare/Google и резерв Yandex/system, Whitelist — system. Они не переносятся. Throne использует ваши DNS-настройки; произвольные URL `.srs` не обязательно участвуют в автоматическом разделении DNS клиента.
- **IPv6 и локальная сеть:** в исходнике IPv6 выключен, а `skip-proxy` и `tun-excluded-routes` заданы в General. Здесь эти параметры не воспроизведены. Проверьте IPv6 и обход локальной сети в Throne отдельно. Без обхода Geo/Whitelist могут отправлять локальный адрес через PROXY; в upstream IP-списке Basic есть даже 127.0.0.1. Обход сети меняет обработку относительно правил, поэтому скрыто не добавляется.
- Группы AUTO/Israel, UDP fallback, ICMP, переписывание URL, сертификаты, JavaScript и YouTube-модули Shadowrocket не переносятся.
- Дополнительный AdBlock/правила клиента могут менять результат. Список Hxehex не гарантирует доступность у оператора и не делает недоступный VPN-сервер достижимым.
- Для первого импорта нужны доступные GitHub/raw.githubusercontent.com или кэш. Дождитесь загрузки всех `.srs`; режим подключения без rule-sets не проверяет этот набор целиком.

## Совместимость со старыми ссылками

`roscom-default`, `roscom-whitelist`, `roscom-mobile` продолжают обновляться по прежней схеме. Они **не переключаются автоматически** на Shadowrocket: импортируйте и выберите `sr-ru-*`.

В старых профилях идут доменные BLOCK → PROXY → DIRECT, затем resolve и IP-правила в том же порядке, остаток PROXY. Это приближение HAPP `IPIfNonMatch`, не полный перенос Happ/INCY/Mihomo. `roscom-mobile` добавляет точные имена Hxehex и ipwhitelist/cidrwhitelist в DIRECT после исключений. DNS и DnsHosts остаются отдельными.

## Обновление и проверка

Actions запускается ежедневно **03:17 UTC / 09:17 Омск**, по **Run workflow** и при изменении сборщика/тестов. Расписание GitHub может задерживаться и отключаться после длительной неактивности репозитория.

Сборка фиксирует коммиты источников, строго разбирает данные, компилирует SRS v3 закреплённым **sing-box 1.12.12**, декомпилирует каждый файл и выполняет `sing-box check` для всех шести профилей с тестовым proxy. Неизвестная конструкция, новая ссылка или неподдержанный порядок no-resolve останавливают сборку вместо потери правил.

Результат публикуется одним коммитом в `rules` с сохранением истории. Затем каждый файл скачивается по публичному HTTPS и проверяется по SHA-256. Ошибка до публикации сохраняет предыдущие файлы; ошибка после push может означать, что публикация состоялась, а проверка доставки не завершилась.

[Запуски workflow](https://github.com/Sannedak/throne-routing/actions/workflows/build.yml) · [manifest.json](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/manifest.json) · [SHA256SUMS](https://raw.githubusercontent.com/Sannedak/throne-routing/rules/SHA256SUMS).

Постоянная база: `https://raw.githubusercontent.com/Sannedak/throne-routing/rules/`. Все `.srs` перечислены в профилях и манифесте. Локально: `python3 -m unittest -v`, затем `python3 build.py --output dist` с установленным sing-box. Выходной каталог должен быть пустым; новый `--cache` нужен для свежего снимка.

После импорта проверьте журнал Throne: Basic — youtube.com через proxy, домен вне списков напрямую; Geo — habr.com через proxy, российский IP напрямую; Whitelist — совпавший IP/имя напрямую, остальное через proxy. Доступность сервера и сайтов проверяется отдельно.

Источники сохраняют условия авторов: [Shadowrocket configuration](https://github.com/misha-tgshv/shadowrocket-configuration-file), [blackmatrix7](https://github.com/blackmatrix7/ios_rule_script), [zkeen_rules](https://github.com/toneywhitez/zkeen_rules), [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip), [RoscomVPN](https://github.com/hydraponique/roscomvpn-routing), [Hxehex](https://github.com/hxehex/russia-mobile-internet-whitelist). Единой лицензии на сторонние базы репозиторий не заявляет.
