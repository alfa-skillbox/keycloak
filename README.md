# Структура проекта

# _docker
Тут лежат скрипты для запуска кейклока и генерации ключа и сертификата для работы с ним по tls
Вся необходимая информация о работе с этой директорией находится в _docker/README.md

# _misc
Тут картинки из видео про https

# _postman
Тут коллекция из видео для тестирования приложения, а также environments для этой коллекции.
Одно без другого не работает

# authorization-code-client
Spring Boot приложение для проверки работы с кейклок по протоколу openid-connect
Оно названо так из-за соответствия процесса его работы флоу процесса авторизации
под названием authorization_code из протокола OAuth2.0 (https://www.rfc-editor.org/rfc/rfc6749#section-4.1)

Для запуска приложения необходимо:
1) убедиться, что поднят кейклок (см. _docker/README.md)
2) прописать в gradle.properties в корне модуля в строке truststore= значение абсолютного
пути до keycloak.truststore в этом модуле
3) запустить приложение через таску bootRun в gradle.build (или gradlew bootRun из терминала)
4) вызвать http://localhost:8081/authorization-code-client/invoke из браузера

# client-credentials-client
Spring Boot приложение для проверки работы с кейклок по протоколу OAuth2.0
Оно названо так из-за соответствия процесса его работы флоу процесса авторизации
под названием client_credentials из протокола OAuth2.0 (https://www.rfc-editor.org/rfc/rfc6749#section-4.4)

Для запуска приложения необходимо:
1) убедиться, что поднят кейклок (см. _docker/README.md)
2) прописать в gradle.properties в корне модуля в строке truststore= значение абсолютного
   пути до keycloak.truststore в этом модуле
3) запустить приложение через таску bootRun в gradle.build (или gradlew bootRun из терминала)
4) вызвать http://localhost:8082/client-credentials-client/invoke из браузера

# resource-server
Spring Boot приложение, выполняющее роль ресурс-сервера в терминологии OAuth2.0 (https://www.rfc-editor.org/rfc/rfc6749#section-1.1)
Оно принимает запросы на ендпоинт /resource-server/client-token, валидирует access_token из заголовка Authorization
через публичный ключ, который получает из кейклок по kid из header части access_token. 
Пояснения про kid и head. Access token имеет форму jwt токена, т.е. имеет структуру {head}.{payload}.{sign}, где
head - мета информация о токене, в том числе kid - идентификатор ключа, которым был подписан access_token
payload - вся полезная информация в виде claim полей
sign - подпись токена, выполненная приватным ключом кейклока
Jwt токен закодирован в base64, поэтому посмотреть его содержимое не проблема, например, на сайте jwt.io 
Пример токена и его расшифровка

eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3SDJ1RS1CQ0ljWDVCaHFiVnVLRmlPeFlXMkN5U0xCRTBGSkZDR3htZktvIn0.eyJleHAiOjE2Njk5MDAxMDUsImlhdCI6MTY2OTkwMDA0NSwiYXV0aF90aW1lIjoxNjY5OTAwMDQ0LCJqdGkiOiJhNWQ2YmI3Zi1kYmNhLTQzYTAtYjIyOC00N2FlNDkyNjVmZTQiLCJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo4NDQzL2F1dGgvcmVhbG1zL2FsZmEtc2tpbGxib3gta2V5Y2xvYWsiLCJzdWIiOiIxM2M2MjE0Yy0zMDk2LTQwZjQtOWU0MC0yZWM5NjM4OGRjMDEiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhdXRob3JpemF0aW9uLWNvZGUtY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6IjVmMWMyMWQ5LWVmMWQtNDI5Zi05YjAzLTJlMTYzZGVlZWY3OCIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1hbGZhLXNraWxsYm94LWtleWNsb2FrIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwic2NvcGUiOiJyZXNvdXJjZS1zZXJ2ZXItc2NvcGUgcHJvZmlsZSIsInNpZCI6IjVmMWMyMWQ5LWVmMWQtNDI5Zi05YjAzLTJlMTYzZGVlZWY3OCIsIm5hbWUiOiJGaXJzdE5hbWUgTGFzdE5hbWUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGZhLXNraWxsYm94IiwiZ2l2ZW5fbmFtZSI6IkZpcnN0TmFtZSIsImZhbWlseV9uYW1lIjoiTGFzdE5hbWUifQ.DS6aAKiTY6najMWj9YXDXacNWsdiGCPqmrkQBO6rDH7zT1L_vFVX0c6rXQlysMtcWmp12JpnpfLjVbEsMce_Suw8O3huIPkXNvpz_Wtynx-NXYon1a2_Tcz4Gsk4Gk3s5BPbG4GahzdCGrGRqFQpMoM_htbAEhvRFIidoNnK0qYiE94cQVrhsBWFDR-9dIhj7AtGFrSDceflpHwC_JzJZ7p9-byXeCDA8JHesdmfxGDHVcu5-dEYOXYjd4j9NUUFB3HZHkYmdFqH-ldEq410LQeMnLjwOTI0DX395vofnONWHs_Y9SH_QBzfop0h-Nuc4czyk1_gpeo-r7EqnLVjMQ

HEADER:ALGORITHM & TOKEN TYPE
{
    "alg": "RS256",
    "typ": "JWT",
    "kid": "7H2uE-BCIcX5BhqbVuKFiOxYW2CySLBE0FJFCGxmfKo"
}
PAYLOAD:DATA
{
    "exp": 1669900105,
    "iat": 1669900045,
    "auth_time": 1669900044,
    "jti": "a5d6bb7f-dbca-43a0-b228-47ae49265fe4",
    "iss": "https://localhost:8443/auth/realms/alfa-skillbox-keycloak",
    "sub": "13c6214c-3096-40f4-9e40-2ec96388dc01",
    "typ": "Bearer",
    "azp": "authorization-code-client",
    "session_state": "5f1c21d9-ef1d-429f-9b03-2e163deeef78",
    "acr": "1",
    "realm_access": {
        "roles": [
            "default-roles-alfa-skillbox-keycloak",
            "offline_access",
            "uma_authorization"
        ]
    },
    "scope": "resource-server-scope profile",
    "sid": "5f1c21d9-ef1d-429f-9b03-2e163deeef78",
    "name": "FirstName LastName",
    "preferred_username": "alfa-skillbox",
    "given_name": "FirstName",
    "family_name": "LastName"
}
VERIFY SIGNATURE
RSASHA256(
base64UrlEncode(header) + "." +
base64UrlEncode(payload))