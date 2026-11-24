# AWS Investigation

### IAM permissions that deserve special attention
During an investigation, look for suspicious use of these actions:

| Action | Why it matters |
| :--- | :--- |
| `iam:CreateAccessKey` | Creates programmatic credentials |
| `iam:CreateUser` | Creates an identity |
| `iam:AttachUserPolicy` | Attaches permissions to a user |
| `iam:AttachRolePolicy` | Attaches permissions to a role |
| `iam:PutUserPolicy` | Adds an inline user policy |
| `iam:PutRolePolicy` | Adds an inline role policy |
| `iam:CreatePolicyVersion` | Creates a new policy version |
| `iam:SetDefaultPolicyVersion` | Changes the active policy version |
| `iam:PassRole` | Allows passing a role to an AWS service |
| `sts:AssumeRole` | Assumes another role |
| `iam:UpdateAccessKey` | Changes an access key's status |


## 9.2 Understand basic Splunk syntax
These are the most useful SPL commands.

| Command | Purpose |
| :--- | :--- |
| `index=` | Selects an index |
| `sourcetype=` | Filters log types |
| `search` | Filters events |
| `table` | Displays selected fields |
| `fields` | Selects or removes fields |
| `stats` | Aggregates results |
| `timechart` | Shows activity over time |
| `sort` | Sorts results |
| `top` | Shows most common values |
| `rare` | Shows uncommon values |
| `dedup` | Removes duplicate results |
| `spath` | Extracts JSON fields |
| `rex` | Extracts fields using regular expressions |
| `eval` | Creates calculated fields |
| `where` | Filters based on expressions |

*Reference: [Splunk Search Command Reference](https://splunk.com)*

## 9.3 Your first Splunk searches
The exact index and sourcetype names depend on how the range environment was configured. Start broadly and inspect the available data.

### Search 1: Discover available log sources
```spl
index=*
| stats count by index sourcetype
| sort - count
```
This tells you:
* Which indexes exist.
* Which log types exist.
* Where your data is stored.

### Search 2: Find AWS CloudTrail events
```spl
index=*
("eventName" OR "eventSource")
| head 100
```
Inspect the events and identify the correct index and sourcetype. After discovering the correct sourcetype, use it in the following searches. For example, if it is `aws:cloudtrail`:
```spl
index=* sourcetype=aws:cloudtrail
| head 50
```

### Search 3: View important CloudTrail fields
```spl
index=* sourcetype=aws:cloudtrail
| spath
| table _time eventName eventSource
        sourceIPAddress userAgent
        userIdentity.type userIdentity.arn
        userIdentity.accessKeyId
        errorCode
| sort _time
```
If fields are not extracted, inspect the raw `_raw` event and adapt the JSON paths.

## 9.4 Investigate IAM activity
Start with:
```spl
index=* sourcetype=aws:cloudtrail
| search eventSource="iam.amazonaws.com"
| spath
| table _time eventName
        userIdentity.arn
        sourceIPAddress
        userAgent
        requestParameters
        errorCode
| sort _time
```
Look for:
* New users.
* New access keys.
* Policy changes.
* New roles.
* Permission escalation.
* Unexpected changes to existing identities.

A more focused search:
```spl
index=* sourcetype=aws:cloudtrail
| search eventName IN (
    "CreateUser",
    "CreateAccessKey",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "AssumeRole"
)
| table _time eventName
        userIdentity.arn
        sourceIPAddress
        userAgent
        errorCode
| sort _time
```
> **Note:** Remember that failed API calls are also useful. A failed permission attempt may reveal what the attacker was trying to access.

## 9.5 Investigate suspicious IP addresses
```spl
index=* sourcetype=aws:cloudtrail
| stats count
        values(eventName) AS actions
        values(userIdentity.arn) AS identities
        by sourceIPAddress
| sort - count
```
This helps you identify:
* Most active source IP addresses.
* Which identities they used.
* What operations were performed.

Do not label an IP as malicious simply because it is unfamiliar. Compare it with known corporate infrastructure and normal application activity.

## 9.6 Investigate AWS access keys
This is one of the most useful searches for your scenario.
```spl
index=* sourcetype=aws:cloudtrail
| spath
| stats count
        values(eventName) AS actions
        values(sourceIPAddress) AS source_ips
        values(userIdentity.arn) AS identities
        by userIdentity.accessKeyId
| sort - count
```
Once you find a suspicious access key, investigate its complete activity:
```spl
index=* sourcetype=aws:cloudtrail
| search "SUSPICIOUS_ACCESS_KEY"
| spath
| table _time eventName eventSource
        sourceIPAddress userAgent
        userIdentity.arn
        requestParameters
        errorCode
| sort _time
```
Replace the placeholder with the actual access key from the investigation. Your objective is to establish what that credential did, and whether its use changed over time.

## 9.7 Investigate S3 activity
```spl
index=* sourcetype=aws:cloudtrail
| search eventSource="s3.amazonaws.com"
| spath
| table _time eventName
        userIdentity.arn
        sourceIPAddress
        requestParameters
        errorCode
| sort _time
```
Look specifically for:
```text
ListBuckets
ListObjectsV2
GetObject
PutObject
DeleteObject
DeleteObjects
PutBucketPolicy
PutBucketAcl
PutBucketVersioning
```
Questions to ask:
* Which buckets were accessed?
* Which identity accessed them?
* Were files downloaded?
* Were files overwritten?
* Were files deleted?
* Were permissions changed?

## 9.8 Investigate role assumption
```spl
index=* sourcetype=aws:cloudtrail
| search eventName="AssumeRole"
| spath
| table _time
        userIdentity.arn
        sourceIPAddress
        requestParameters.roleArn
        requestParameters.roleSessionName
        responseElements
        errorCode
| sort _time
```
Determine whether an unexpected identity assumed a privileged role. Then search all events associated with that role session and its temporary access key.

## 9.9 Investigate failed AWS requests
```spl
index=* sourcetype=aws:cloudtrail
| search errorCode=*
| stats count
        values(eventName) AS attempted_actions
        values(errorCode) AS errors
        by sourceIPAddress userIdentity.arn
| sort - count
```
**Why is this useful?**
An attacker might attempt several API operations and receive `AccessDenied` responses. This may reveal:
* Their intended target.
* Their understanding of AWS services.
* Their attempts to expand privileges.
* Which permissions were missing.

A failed request is not proof of successful compromise, but it can provide valuable investigative context.

---

## 10. Linux and application log searches in Splunk
You should correlate Linux activity with AWS activity. For example:
* At `09:15`, someone requests a suspicious application URL.
* At `09:16`, the application logs an error.
* At `09:18`, an AWS access key starts being used from an unusual IP.
* At `09:20`, the same identity starts discovering S3 resources.

This correlation can help establish the relationship between the web application and the AWS compromise.

## 10.1 Find Linux authentication events
First, identify the Linux sourcetypes:
```spl
index=*
| search "sshd" OR "sudo" OR "authentication"
| stats count by sourcetype
```
Then investigate:
```spl
index=* ("Failed password" OR "Accepted password")
| table _time host source sourcetype _raw
| sort _time
```
Look for:
* Repeated failed login attempts.
* Successful logins from unfamiliar IPs.
* Unexpected accounts.
* Successful login after repeated failures.

## 10.2 Find sudo activity
```spl
index=* ("sudo" OR "COMMAND=")
| table _time host user _raw
| sort _time
```
Investigate whether an unexpected user executed commands with elevated privileges.

## 10.3 Investigate application access logs
If the application uses Nginx, Apache, or another web server:
```spl
index=* ("GET " OR "POST ")
| table _time host source _raw
| sort _time
```
Look for suspicious requests involving:
* Configuration files.
* Environment files.
* Unexpected upload endpoints.
* Unusual HTTP methods.
* Repeated application errors.
* Unexpected access to administrative endpoints.

Do not assume that a request for a sensitive filename means the file was successfully retrieved. Check the HTTP status code and corroborating evidence.

## 10.4 Find unusual HTTP responses
```spl
index=* ("HTTP/1.1" OR "HTTP/2")
| stats count by status
| sort - count
```
The field might not be called `status` in your environment. Inspect the raw events first. Pay particular attention to:

| HTTP Status | Meaning |
| :--- | :--- |
| `401` | Unauthorized |
| `403` | Forbidden |
| `404` | Not Found |
| `500` | Internal Server Error |

These codes need context. For example, a `404` may be a harmless typo or an automated attempt to locate sensitive files.

## 10.5 Build an event timeline
Once you identify suspicious activity:
```spl
index=*
| sort 0 _time
| table _time host sourcetype source _raw
```
This is useful for building a chronological incident timeline. You can narrow the search by suspicious host, IP, username, or access key once those indicators are established.

## 10.6 Build activity charts
For AWS events:
```spl
index=* sourcetype=aws:cloudtrail
| timechart span=15m count by eventSource
```
For API operations:
```spl
index=* sourcetype=aws:cloudtrail
| timechart span=15m count by eventName
```

