# Credential research: OpenAI API keys

## Recognition

OpenAI API keys are bearer tokens that start with `sk-`
([API reference: authentication][auth]). Current keys carry a type prefix: `sk-proj-` for
project keys, the recommended type, and `sk-admin-` for organization Admin API keys
([Admin API keys][admin]). A plain `sk-` key is a legacy user key. Public scanner rules
also anchor on the `T3BlbkFJ` marker (base64 for "OpenAI") found inside most keys, an
observed but undocumented pattern. To reduce false positives, require the prefix, the
marker and word boundaries, and reject placeholders (`sk-...`) and low-entropy values.

## Safe validation

Only test keys you own or are explicitly authorized to test. The safest setup is a
disposable key in a dedicated project, restricted to read access
([key permissions][perms]). Send one request to a no-cost endpoint over HTTPS:
`GET /v1/models` ([List models][models]). A `200` means the key is active and a `401`
means it is revoked or invalid. A `403` reporting missing scopes means the key is valid
but restricted. Never call billable endpoints, never log the key, and revoke it after
testing. A leaked third-party key is never tested: it is reported to its owner.

## Ownership and permissions

The key string encodes no owner. API responses include an `openai-organization` header
naming the organization ([debugging requests][auth]), and a project key is scoped to a
single project. Permissions (All, Restricted, Read only) can only be inferred from
`403` errors. Without the owner's Admin API access, you cannot determine who created the
key, the project's name, spending limits or usage history.

[auth]: https://developers.openai.com/api/docs/api-reference/introduction
[admin]: https://developers.openai.com/api/reference/resources/organization/subresources/admin_api_keys/index.md
[perms]: https://help.openai.com/en/articles/8867743-assign-api-key-permissions
[models]: https://developers.openai.com/api/reference/resources/models/methods/list/index.md
