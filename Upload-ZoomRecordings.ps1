param (
	$api_key = "xxxxxxxxxxxxxxxx",
	$api_secret = "xxxxxxxxxxxxxxxxxxxx",
	$ssid_token = "xxxxxxxxxxxxxxxxxxxx",
	$StorageAccountName = "xxxxxxxxx",
	$StorageAccountKey = "xxxxx"
)

function Generate-JWT (
    [Parameter(Mandatory = $True)]
    [ValidateSet("HS256", "HS384", "HS512")]
    $Algorithm = $null,
    $type = $null,
    [Parameter(Mandatory = $True)]
    [string]$Issuer = $null,
    [int]$ValidforSeconds = $null,
    [Parameter(Mandatory = $True)]
    $SecretKey = $null
    ){

    $exp = [int][double]::parse((Get-Date -Date $((Get-Date).addseconds($ValidforSeconds).ToUniversalTime()) -UFormat %s)) # Grab Unix Epoch Timestamp and add desired expiration.

    [hashtable]$header = @{alg = $Algorithm; typ = $type}
    [hashtable]$payload = @{iss = $Issuer; exp = $exp}

    $headerjson = $header | ConvertTo-Json -Compress
    $payloadjson = $payload | ConvertTo-Json -Compress
    
    $headerjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($headerjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')
    $payloadjsonbase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadjson)).Split('=')[0].Replace('+', '-').Replace('/', '_')

    $ToBeSigned = $headerjsonbase64 + "." + $payloadjsonbase64

    $SigningAlgorithm = switch ($Algorithm) {
        "HS256" {New-Object System.Security.Cryptography.HMACSHA256}
        "HS384" {New-Object System.Security.Cryptography.HMACSHA384}
        "HS512" {New-Object System.Security.Cryptography.HMACSHA512}
    }

    $SigningAlgorithm.Key = [System.Text.Encoding]::UTF8.GetBytes($SecretKey)
    $Signature = [Convert]::ToBase64String($SigningAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ToBeSigned))).Split('=')[0].Replace('+', '-').Replace('/', '_')
    
    $token = "$headerjsonbase64.$payloadjsonbase64.$Signature"
    $token
}


function Upload-FileToAzureStorageContainer {
    [cmdletbinding()]
    param(
        $StorageAccountName,
        $StorageAccountKey,
        $ContainerName,
        $sourceFile,
        $targetPath,
        $Force
    )

    $ctx = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey
    $container = Get-AzureStorageContainer -Name $ContainerName -Context $ctx

    $container.CloudBlobContainer.Uri.AbsoluteUri
    if ($container) {
        $filesToUpload = Get-Item $sourceFile
        Set-AzureStorageBlobContent -File $filesToUpload.fullname -Container $container.Name -Blob $targetPath -Context $ctx -Force:$Force | Out-Null
    }
}

function Download-FileFromZoom {

    [cmdletbinding()]
    param(
        $URL,
		$ssid_token
    )

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    
$cookie = New-Object System.Net.Cookie 

$cookie.Name = "_zm_ssid"
$cookie.Value = $ssid_token
$cookie.Domain = ".zoom.us"

$session.Cookies.Add($cookie);

$res = Invoke-WebRequest $URL -WebSession $session -TimeoutSec 900 -Method Head

if ($res.Headers['Content-Disposition'] -match 'filename=')
{
    $filename = ($res.Headers['Content-Disposition'].Split(";") | Where-Object { $_ -match 'filename=' }) -replace 'filename=', ""
}
else
{
$filename = $res.BaseResponse.ResponseUri.AbsolutePath.Split('/')[-1]
}
Invoke-WebRequest $URL -WebSession $session -TimeoutSec 900 -OutFile $filename

return $filename

}



# Generate JWT for use in API calls.
$base_uri = "https://api.zoom.us/v2"

$token = Generate-JWT -Algorithm 'HS256' -type 'JWT' -Issuer $api_key -SecretKey $api_secret -ValidforSeconds 3000

# Generate Header for API calls.
[string]$contentType = 'application/json'
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add('Content-Type' , $contentType)
$headers.Add('Authorization','Bearer ' + $token)    
 
# Pull all API device data.
$query_result = Invoke-RestMethod -Uri "$base_uri/users?status=active&page_size=300&page_number=1" -Headers $headers -Method GET

$meetings = @()


Foreach ( $user in ($query_result.users) ) {

for ($i=1;$i -lt 7; $i++)
 {
 $startDate = (Get-Date).AddMonths(-$i).AddDays(1).tostring("yyyy-MM-dd")
 $endDate = (Get-Date).AddMonths(-$i + 1).tostring("yyyy-MM-dd")
 $startdate + ":::" + $enddate + ":::" + $user.first_name

 $meetings = $meetings + (Invoke-RestMethod -Uri "$base_uri/users/$($user.id)/recordings?from=$startDate&to=$endDate&page_size=10000" -Headers $headers -Method GET).meetings
 $meetings.Count
}

}

foreach ( $meeting in $meetings ) {

$ContainerName = "zoom"

$meeting.recording_files | foreach {

    $sourceFile = Download-FileFromZoom -URL $_.download_url -ssid_token $ssid_token
    $path = $meeting.topic
    if (!$path) { $path = "TopicMissing" }
    Upload-FileToAzureStorageContainer -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey -ContainerName $ContainerName -targetPath "$path/$sourceFile" -sourceFile $sourceFile
}
}
