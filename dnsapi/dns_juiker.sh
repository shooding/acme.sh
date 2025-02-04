#!/usr/bin/env sh
# shellcheck disable=SC2034
dns_juiker_info='Juiker Cloud DNS
Site: https://tw.juiker.net
Docs: github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_juiker
Options:
 JUIKER_AUTH_ENDPOINT endpoint for authentication
 JUIKER_DNS_ENDPOINT endpoint for DNS management
 JUIKER_DEVELOPER_ID Developer ID
 JUIKER_DEVELOPER_SECRET Developer Secret
'

########  Public functions #####################

#Usage: add  _acme-challenge.www.domain.com   "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_juiker_add() {
  fulldomain=$1
  txtvalue=$2

  JUIKER_DEVELOPER_ID="${JUIKER_DEVELOPER_ID:-$(_readaccountconf_mutable JUIKER_DEVELOPER_ID)}"
  JUIKER_DEVELOPER_SECRET="${JUIKER_DEVELOPER_SECRET:-$(_readaccountconf_mutable JUIKER_DEVELOPER_SECRET)}"
  JUIKER_TOKEN="${JUIKER_TOKEN:-$(_readaccountconf_mutable JUIKER_TOKEN)}"
    
  if [ -z "$JUIKER_DEVELOPER_ID" ] || [ -z "$JUIKER_DEVELOPER_SECRET" ]; then
    JUIKER_DEVELOPER_ID=""
    JUIKER_DEVELOPER_SECRET=""
    _err "You haven't specified the juiker developer key id and and developer secret yet."
    _err "Please create your key and try again."
    return 1
  fi

  _debug "First detect the root zone"
  if ! _get_root "$fulldomain"; then
    _err "invalid domain"
    _sleep 1
    return 1
  fi
  _debug _domain_id "$_domain_id"
  _debug _sub_domain "$_sub_domain"
  _debug _domain "$_domain"

  _info "Getting existing records for $fulldomain"
  if ! _juiker_rest GET "2013-04-01$_domain_id/rrset" "name=$fulldomain&type=TXT"; then
    _sleep 1
    return 1
  fi

  if echo "$response" | jq -e --arg fd "$fulldomain." '
     .ResourceRecordSets[]?
     | select(.Name == $fd and .Type == "TXT")' > /dev/null; then
    _info "The TXT record already exists. Skipping."
    return 0
  fi

  _debug "Adding records"

  # Juiker uses the same structure as AWS Route53.
  # _aws_tmpl_xml="<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/2013-04-01/\"><ChangeBatch><Changes><Change><Action>UPSERT</Action><ResourceRecordSet><Name>$fulldomain</Name><Type>TXT</Type><TTL>300</TTL><ResourceRecords>$_resource_record<ResourceRecord><Value>\"$txtvalue\"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"
  _aws_tmpl_json='{
  "changeBatch": {
    "changes": [
      {
        "action": "UPSERT",
        "resourceRecordSet": {
          "name": "'${fulldomain}'",
          "type": "TXT",
          "ttl": 300,
          "resourceRecords": [
            {
              "value": "\"'${txtvalue}'\""
            }
          ]
        }
      }
    ]
  }
}'

  if _juiker_rest POST "2013-04-01$_domain_id/rrset/" "" "$_aws_tmpl_json" && echo "$response" | jq -e '
    .ChangeResourceRecordSetsResponse?
    | select(.ChangeInfo.Status == "PENDING")
  ' > /dev/null 2>&1; then
    _info "TXT record updated successfully."    
    _sleep 1    

    return 0
  fi
  _sleep 1
  return 1
}

#fulldomain txtvalue
dns_juiker_rm() {
    
  _debug "Juiker DNS API supports only update operation. Your TXT record will be kept for next challenge."
  return 0

}

####################  Private functions below ##################################

_get_root() {
  domain=$1
  i=1
  p=1

  # iterate over subdomains, e.g.: a.b.c.d -> b.c.d -> c.d -> d
  while true; do
    # cut off $i fields from the front. For example: i=1 -> "a.b.c.d"
    # h=$(printf "%s" "$domain" | cut -d . -f ${i}-100 | sed 's/\./\\./g')
    # mydomain\.com. rather than mydomain.com. in your JSON, which won’t match if the JSON actually has
    # Just cut the domain. Don't do sed 's/\./\\./g' anymore
    h=$(printf "%s" "$domain" | cut -d . -f ${i}-100)

    _debug "Checking domain: $h"
    if [ -z "$h" ]; then
      _err "invalid domain when get_root"
      return 1
    fi

    # Call the relay's "list hosted zones" endpoint, store JSON response in $response
    _juiker_rest GET "2013-04-01/hostedzone"

    while true; do
      # Use jq to search for a HostedZone that matches .Name == "$h." and PrivateZone == false.
      # The 'first' filter returns just the first matching object or null if not found.
      # -c means output in compact form on a single line.
      hostedzone="$(echo "$response" | jq -c --arg h "$h." '[.HostedZones[] | select(.Name == $h and .Config.PrivateZone == false)] | first')"

      _debug "hostedzone: $hostedzone"

      # If 'hostedzone' is "null" or empty, it means no match found on this page.
      if [ -n "$hostedzone" ] && [ "$hostedzone" != "null" ]; then
        # Extract the "Id" field from that JSON object.
        _domain_id="$(echo "$hostedzone" | jq -r '.Id')"
        _debug "_domain_id: $_domain_id"

        if [ -n "$_domain_id" ]; then
          _sub_domain="$(printf "%s" "$domain" | cut -d . -f 1-"$p")"
          _domain="$h"
          return 0
        fi
        _err "Can't find domain with id: $h"
        return 1
      fi

      # If not found on this page, check if "IsTruncated" is true and "NextMarker" is non-null.
      isTruncated="$(echo "$response" | jq -r '.IsTruncated')"
      nextMarker="$(echo "$response" | jq -r '.NextMarker')"
      if [ "$isTruncated" = "true" ] && [ "$nextMarker" != "null" ]; then
        _debug "IsTruncated"
        _debug "NextMarker: $nextMarker"
        # Query the next page.
        _juiker_rest GET "2013-04-01/hostedzone" "marker=$nextMarker"
      else
        # No more pages.
        break
      fi
    done

    # Move to the next portion, e.g. from "a.b.c.d" -> "b.c.d"
    p=$i
    i=$((i+1))
  done

  return 1
}

_juiker_rest() {
  mtd="$1"
  ep="$2"
  qsr="$3"
  data="$4"

  _debug mtd "$mtd"
  _debug ep "$ep"
  _debug qsr "$qsr"
  _debug data "$data"

  if [ ! "$JUIKER_TOKEN" ]; then
    _debug "Get developer token"
    _juiker_auth
  else
    _debug "Token already exists. Skip get developer token."
  fi

  token_trimmed=$(echo "$JUIKER_TOKEN" | tr -d '"')

  export _H1="Content-Type: application/json"
  export _H2="Authorization: Bearer $token_trimmed"
  _debug _H2 "$_H2"

  url="$JUIKER_DNS_ENDPOINT/$ep"
  if [ "$qsr" ]; then
    url="$JUIKER_DNS_ENDPOINT/$ep?$qsr"
  fi

  if [ "$mtd" = "GET" ]; then
    response="$(_get "$url")"
  else
    response="$(_post "$data" "$url")"
  fi

  _ret="$?"
  _debug2 response "$response"
  if [ "$_ret" = "0" ]; then    
    if _contains "$response" "error"; then
      _err "Response error:$response"
      return 1
    fi
  fi

  return "$_ret"
}

_juiker_auth() {
  _debug "Authenticating using Basic Authentication"

  JUIKER_DEVELOPER_ID="${JUIKER_DEVELOPER_ID:-$(_readaccountconf_mutable JUIKER_DEVELOPER_ID)}"
  JUIKER_DEVELOPER_SECRET="${JUIKER_DEVELOPER_SECRET:-$(_readaccountconf_mutable JUIKER_DEVELOPER_SECRET)}"  

  # Create the basic auth credentials: base64("JUIKER_DEVELOPER_ID:JUIKER_DEVELOPER_SECRET")
  # using acme.sh's _base64 function.
  _basic_auth=$(printf "%s:%s" "$JUIKER_DEVELOPER_ID" "$JUIKER_DEVELOPER_SECRET" | _base64)
  
  # Set necessary headers for the HTTP request.
  export _H1="Content-Type: application/json"
  export _H2="Authorization: Basic ${_basic_auth}"
  
  # Prepare the JSON payload. Adjust this if your API expects additional or different data.
  data='{"scope":"tw:pix:dns"}'

  # Define the endpoint to which the authentication request is made.  
  _auth_url="${JUIKER_AUTH_ENDPOINT}/oauth2/getDeveloperToken"
  _debug "Calling auth endpoint: ${_auth_url}"

  # Post the data using acme.sh's _post function.
  response="$(_post "$data" "$_auth_url" "" "POST")"

  # Check for errors in the _post call.
  if [ "$?" != "0" ]; then
    _err "Error calling authentication endpoint at ${_auth_url}"
    return 1
  fi

  _debug2 "Authentication response:" "$response"

  # Extract the token from the JSON response.
  # This extraction assumes the response contains a key "accessToken".  
  JUIKER_TOKEN="$(echo "$response" | _normalizeJson | _egrep_o "\"accessToken\"[^,]*" | _egrep_o "[^:]*$" | tr -d '"}')"
  
  if [ -z "$JUIKER_TOKEN" ]; then
    _err "Authentication token not found in response."
    return 1
  fi

  _debug "Obtained JUIKER token: $JUIKER_TOKEN"  
  return 0
}
