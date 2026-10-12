# Dashboard

Static page, no build step. It logs in with the Cognito hosted page and reads the HTTP API.

```
cp config.example.js config.js     # fill it with `terraform output` of backend/infra
python3 -m http.server 5173
```

Open http://localhost:5173. That origin is the default of `dashboard_origins` in Terraform; if you serve
the page from another origin, add it to that variable before applying.

`config.js` is ignored by git. Nothing in it is a secret (API URL, public client id, login URL), but it is
different for every deployment.
