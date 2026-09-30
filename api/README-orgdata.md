# The data endpoints every service keeps

Each service that holds anything about an org or a person adds these to its
own contract, word for word apart from the service name, and answers with the
shapes in `pkg/orgdata`. Only the organization service calls them
(`auth.RequireService(ctx, orgdata.Caller)`), from its daily loop.

- **Export** returns every record the service keeps for the org as one JSON
  document (`data`), plus the storage keys of files that belong with them
  (`files`). No secrets: credentials, tokens and hashes are left out, and the
  export says so where it matters.
- **Purge** deletes every row of the org in the service's schema, in
  dependency order, then counts what is left and returns it. It is
  idempotent; a second call returns `remaining: 0` having done nothing.
  Files are removed by the organization service with `storage.DeleteAll`.
- **Personal export** returns what the service keeps about one person: the
  user id, and each of their memberships as `membership=org:membership`
  query parameters. Only their own records: never other people's messages to
  them.
- **Forget a membership** (only where the service keeps something personal
  under a membership: usage, calendar, notification) deletes it, for account
  deletion.

```yaml
  /v1/internal/organizations/{org_id}/data:
    get:
      operationId: exportOrgData
      summary: Everything this service keeps for an org, for its export (the organization service only)
      tags: [internal]
      parameters:
        - $ref: '#/components/parameters/OrgId'
      responses:
        '200':
          description: This service's part of the export
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DataPart'
        '403':
          $ref: '#/components/responses/Error'
        default:
          $ref: '#/components/responses/Error'
    delete:
      operationId: purgeOrgData
      summary: Delete everything this service keeps for an org, and count what is left (the organization service only)
      tags: [internal]
      parameters:
        - $ref: '#/components/parameters/OrgId'
      responses:
        '200':
          description: Purged; remaining is zero when nothing of the org is left
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DataPurged'
        '403':
          $ref: '#/components/responses/Error'
        default:
          $ref: '#/components/responses/Error'
  /v1/internal/users/{user_id}/data:
    get:
      operationId: exportUserData
      summary: What this service keeps about one person, for their own export (the organization service only)
      tags: [internal]
      parameters:
        - name: user_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
        - name: membership
          in: query
          description: Each of the person's memberships, as org_id:membership_id.
          schema:
            type: array
            items:
              type: string
      responses:
        '200':
          description: This service's part of the person's export
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/DataPart'
        '400':
          $ref: '#/components/responses/Error'
        '403':
          $ref: '#/components/responses/Error'
        default:
          $ref: '#/components/responses/Error'
  # Only in usage, calendar and notification:
  /v1/internal/organizations/{org_id}/memberships/{membership_id}/data:
    delete:
      operationId: forgetMembershipData
      summary: Delete what this service keeps personally under one membership, for account deletion (the organization and user services only)
      tags: [internal]
      parameters:
        - $ref: '#/components/parameters/OrgId'
        - name: membership_id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '204':
          description: Forgotten
        '403':
          $ref: '#/components/responses/Error'
        default:
          $ref: '#/components/responses/Error'

# components/schemas:
    DataPart:
      type: object
      required: [service, data, files]
      properties:
        service:
          type: string
        data:
          type: object
          additionalProperties: true
        files:
          type: array
          items:
            type: object
            required: [key, name]
            properties:
              key:
                type: string
              name:
                type: string
    DataPurged:
      type: object
      required: [remaining]
      properties:
        remaining:
          type: integer
```
