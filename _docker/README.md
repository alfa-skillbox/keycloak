## Keycloak
### Процедура запуска докер контейнеров
keycloak_up.sh - билдит и запускает контейнер keycloak
Если браузер стопорит загрузку без https, то 
инфа по hsts вам в помощь
https://www.ssl2buy.com/wiki/how-to-clear-hsts-settings-on-chrome-firefox-and-ie-browsers#:~:text=Clearing%20HSTS%20in%20Chrome&text=Open%20Google%20Chrome,simply%20press%20the%20Delete%20button
keycloak_down.sh - стопает сервис и удаляет контейнер keycloak и его volumes

### Получение конфигурации кейклока
Зайти в терминале в директорию /_docker/utils/keycloak и запустить backup-keycloak.sh

### Генерация ключа и сертификата для tls в кейклоке 
keycloak_certs_and_truststore_generator.sh - сгенерит нужные ключи и разложит в нужные директории:
 а) в _docker/imports/keycloak отправятся tls.crt (самоподписанный сертификат) и tls.key (приватный ключ)
 б) в authorization-code-client/src/main/resources, /client-credentials-client/src/main/resources и
/resource-server/src/main/resources отправятся одинаковые keycloak.truststore 
(хранилище самоподписанного сертификата) для работы с поднятым на локалке кейклок через https

Внимание! перед запуском скрипта keycloak_certs_and_truststore_generator.sh 
удалите tls.crt, tls.key и keycloak.truststore

### Работа кейклока с браузером и постманом
Здесь для https генерятся самоподписанные сертификаты, поэтому для установления https при ввзаимодействии с кейклок
необходимо установить в браузере (зависит от вашего браузера) и в постмане (через settings - certificates) tls.crt 