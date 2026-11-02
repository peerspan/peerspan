# Endpoints

- `POST /orders`: when throttled, answers 429 with `Retry-After: 37`.
- `GET /catalog`: default page size 80.
- `POST /image-resize`: `width` defaults to 480. The largest allowed `width` is 1024.
