<?php
/*
miniProxy - A simple PHP web proxy. <https://github.com/joshdick/miniProxy>
Written and maintained by Joshua Dick <http://joshdick.net>.
miniProxy is licensed under the GNU GPL v3 <http://www.gnu.org/licenses/gpl.html>.
*/

/****************************** START CONFIGURATION ******************************/

//To allow proxying any URL, set $whitelistPatterns to an empty array (the default).
//To only allow proxying of specific URLs (whitelist), add corresponding regular expressions
//to the $whitelistPatterns array. Enter the most specific patterns possible, to prevent possible abuse.
//You can optionally use the "getHostnamePattern()" helper function to build a regular expression that
//matches all URLs for a given hostname.
$whitelistPatterns = array(
  //Usage example: To support any URL at example.net, including sub-domains, uncomment the
  //line below (which is equivalent to [ @^https?://([a-z0-9-]+\.)*example\.net@i ]):
  //getHostnamePattern("example.net")
);

//To enable CORS (cross-origin resource sharing) for proxied sites, set $forceCORS to true.
$forceCORS = false;

//Set to false to report the client machine's IP address to proxied sites via the HTTP `x-forwarded-for` header.
//Setting to false may improve compatibility with some sites, but also exposes more information about end users to proxied sites.
$anonymize = true;

//Start/default URL that that will be proxied when miniProxy is first loaded in a browser/accessed directly with no URL to proxy.
//If empty, miniProxy will show its own landing page.
$startURL = "";

//When no $startURL is configured above, miniProxy will show its own landing page with a URL form field
//and the configured example URL. The example URL appears in the instructional text on the miniProxy landing page,
//and is proxied when pressing the 'Proxy It!' button on the landing page if its URL form is left blank.
$landingExampleURL = "https://www.google.com/";

/****************************** END CONFIGURATION ******************************/

ob_start("ob_gzhandler");

if (version_compare(PHP_VERSION, "5.4.7", "<")) {
  die("miniProxy requires PHP version 5.4.7 or later.");
}

$requiredExtensions = ["curl", "mbstring", "xml"];
foreach($requiredExtensions as $requiredExtension) {
  if (!extension_loaded($requiredExtension)) {
    die("miniProxy requires PHP's \"" . $requiredExtension . "\" extension. Please install/enable it on your server and try again.");
  }
}

//Helper function for use inside $whitelistPatterns.
//Returns a regex that matches all HTTP[S] URLs for a given hostname.
function getHostnamePattern($hostname) {
  $escapedHostname = str_replace(".", "\.", $hostname);
  return "@^https?://([a-z0-9-]+\.)*" . $escapedHostname . "@i";
}

//Helper function used to removes/unset keys from an associative array using case insensitive matching
function removeKeys(&$assoc, $keys2remove) {
  $keys = array_keys($assoc);
  $map = array();
  $removedKeys = array();
  foreach ($keys as $key) {
    $map[strtolower($key)] = $key;
  }
  foreach ($keys2remove as $key) {
    $key = strtolower($key);
    if (isset($map[$key])) {
      unset($assoc[$map[$key]]);
      $removedKeys[] = $map[$key];
    }
  }
  return $removedKeys;
}

if (!function_exists("getallheaders")) {
  //Adapted from http://www.php.net/manual/en/function.getallheaders.php#99814
  function getallheaders() {
    $result = array();
    foreach($_SERVER as $key => $value) {
      if (substr($key, 0, 5) == "HTTP_") {
        $key = str_replace(" ", "-", ucwords(strtolower(str_replace("_", " ", substr($key, 5)))));
        $result[$key] = $value;
      }
    }
    return $result;
  }
}

$usingDefaultPort =  (!isset($_SERVER["HTTPS"]) && $_SERVER["SERVER_PORT"] === 80) || (isset($_SERVER["HTTPS"]) && $_SERVER["SERVER_PORT"] === 443);
$prefixPort = $usingDefaultPort ? "" : ":" . $_SERVER["SERVER_PORT"];
//Use HTTP_HOST to support client-configured DNS (instead of SERVER_NAME), but remove the port if one is present
$prefixHost = $_SERVER["HTTP_HOST"];
$prefixHost = strpos($prefixHost, ":") ? implode(":", explode(":", $_SERVER["HTTP_HOST"], -1)) : $prefixHost;

define("PROXY_PREFIX", "http" . (isset($_SERVER["HTTPS"]) ? "s" : "") . "://" . $prefixHost . $prefixPort . $_SERVER["SCRIPT_NAME"] . "?");

//Makes an HTTP request via cURL, using request data that was passed directly to this script.
function makeRequest($url) {

  global $anonymize;

  //Tell cURL to make the request using the brower's user-agent if there is one, or a fallback user-agent otherwise.
  $user_agent = $_SERVER["HTTP_USER_AGENT"];
  if (empty($user_agent)) {
    $user_agent = "Mozilla/5.0 (compatible; miniProxy)";
  }
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);

  //Get ready to proxy the browser's request headers...
  $browserRequestHeaders = getallheaders();

  //...but let cURL set some headers on its own.
  $removedHeaders = removeKeys($browserRequestHeaders, array(
    "Accept-Encoding", //Throw away the browser's Accept-Encoding header if any and let cURL make the request using gzip if possible.
    "Content-Length",
    "Host",
    "Origin"
  ));

  $removedHeaders = array_map("strtolower", $removedHeaders);

  curl_setopt($ch, CURLOPT_ENCODING, "");
  //Transform the associative array from getallheaders() into an
  //indexed array of header strings to be passed to cURL.
  $curlRequestHeaders = array();
  foreach ($browserRequestHeaders as $name => $value) {
    $curlRequestHeaders[] = $name . ": " . $value;
  }
  if (!$anonymize) {
    $curlRequestHeaders[] = "X-Forwarded-For: " . $_SERVER["REMOTE_ADDR"];
  }
  //Any `origin` header sent by the browser will refer to the proxy itself.
  //If an `origin` header is present in the request, rewrite it to point to the correct origin.
  if (in_array("origin", $removedHeaders)) {
    $urlParts = parse_url($url);
    $port = $urlParts["port"];
    $curlRequestHeaders[] = "Origin: " . $urlParts["scheme"] . "://" . $urlParts["host"] . (empty($port) ? "" : ":" . $port);
  };
  curl_setopt($ch, CURLOPT_HTTPHEADER, $curlRequestHeaders);

  //Proxy any received GET/POST/PUT data.
  switch ($_SERVER["REQUEST_METHOD"]) {
    case "POST":
      curl_setopt($ch, CURLOPT_POST, true);
      //For some reason, $HTTP_RAW_POST_DATA isn't working as documented at
      //http://php.net/manual/en/reserved.variables.httprawpostdata.php
      //but the php://input method works. This is likely to be flaky
      //across different server environments.
      //More info here: http://stackoverflow.com/questions/8899239/http-raw-post-data-not-being-populated-after-upgrade-to-php-5-3
      //If the miniProxyFormAction field appears in the POST data, remove it so the destination server doesn't receive it.
      $postData = Array();
      parse_str(file_get_contents("php://input"), $postData);
      if (isset($postData["miniProxyFormAction"])) {
        unset($postData["miniProxyFormAction"]);
      }
      curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    break;
    case "PUT":
      curl_setopt($ch, CURLOPT_PUT, true);
      curl_setopt($ch, CURLOPT_INFILE, fopen("php://input", "r"));
    break;
  }

  //Other cURL options.
  curl_setopt($ch, CURLOPT_HEADER, true);
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

  //Set the request URL.
  curl_setopt($ch, CURLOPT_URL, $url);

  //Make the request.
  $response = curl_exec($ch);
  $responseInfo = curl_getinfo($ch);
  $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
  curl_close($ch);

  //Setting CURLOPT_HEADER to true above forces the response headers and body
  //to be output together--separate them.
  $responseHeaders = substr($response, 0, $headerSize);
  $responseBody = substr($response, $headerSize);

  return array("headers" => $responseHeaders, "body" => $responseBody, "responseInfo" => $responseInfo);
}

//Converts relative URLs to absolute ones, given a base URL.
//Modified version of code found at http://nashruddin.com/PHP_Script_for_Converting_Relative_to_Absolute_URL
function rel2abs($rel, $base) {
  if (empty($rel)) $rel = ".";
  if (parse_url($rel, PHP_URL_SCHEME) != "" || strpos($rel, "//") === 0) return $rel; //Return if already an absolute URL
  if ($rel[0] == "#" || $rel[0] == "?") return $base.$rel; //Queries and anchors
  extract(parse_url($base)); //Parse base URL and convert to local variables: $scheme, $host, $path
  $path = isset($path) ? preg_replace("#/[^/]*$#", "", $path) : "/"; //Remove non-directory element from path
  if ($rel[0] == "/") $path = ""; //Destroy path if relative url points to root
  $port = isset($port) && $port != 80 ? ":" . $port : "";
  $auth = "";
  if (isset($user)) {
    $auth = $user;
    if (isset($pass)) {
      $auth .= ":" . $pass;
    }
    $auth .= "@";
  }
  $abs = "$auth$host$port$path/$rel"; //Dirty absolute URL
  for ($n = 1; $n > 0; $abs = preg_replace(array("#(/\.?/)#", "#/(?!\.\.)[^/]+/\.\./#"), "/", $abs, -1, $n)) {} //Replace '//' or '/./' or '/foo/../' with '/'
  return $scheme . "://" . $abs; //Absolute URL is ready.
}

//Proxify contents of url() references in blocks of CSS text.
function proxifyCSS($css, $baseURL) {
  // Add a "url()" wrapper to any CSS @import rules that only specify a URL without the wrapper,
  // so that they're proxified when searching for "url()" wrappers below.
  $sourceLines = explode("\n", $css);
  $normalizedLines = [];
  foreach ($sourceLines as $line) {
    if (preg_match("/@import\s+url/i", $line)) {
      $normalizedLines[] = $line;
    } else {
      $normalizedLines[] = preg_replace_callback(
        "/(@import\s+)([^;\s]+)([\s;])/i",
        function($matches) use ($baseURL) {
          return $matches[1] . "url(" . $matches[2] . ")" . $matches[3];
        },
        $line);
    }
  }
  $normalizedCSS = implode("\n", $normalizedLines);
  return preg_replace_callback(
    "/url\((.*?)\)/i",
    function($matches) use ($baseURL) {
        $url = $matches[1];
        //Remove any surrounding single or double quotes from the URL so it can be passed to rel2abs - the quotes are optional in CSS
        //Assume that if there is a leading quote then there should be a trailing quote, so just use trim() to remove them
        if (strpos($url, "'") === 0) {
          $url = trim($url, "'");
        }
        if (strpos($url, "\"") === 0) {
          $url = trim($url, "\"");
        }
        if (stripos($url, "data:") === 0) return "url(" . $url . ")"; //The URL isn't an HTTP URL but is actual binary data. Don't proxify it.
        return "url(" . PROXY_PREFIX . rel2abs($url, $baseURL) . ")";
    },
    $normalizedCSS);
}

//Proxify "srcset" attributes (normally associated with <img> tags.)
function proxifySrcset($srcset, $baseURL) {
  $sources = array_map("trim", explode(",", $srcset)); //Split all contents by comma and trim each value
  $proxifiedSources = array_map(function($source) use ($baseURL) {
    $components = array_map("trim", str_split($source, strrpos($source, " "))); //Split by last space and trim
    $components[0] = PROXY_PREFIX . rel2abs(ltrim($components[0], "/"), $baseURL); //First component of the split source string should be an image URL; proxify it
    return implode($components, " "); //Recombine the components into a single source
  }, $sources);
  $proxifiedSrcset = implode(", ", $proxifiedSources); //Recombine the sources into a single "srcset"
  return $proxifiedSrcset;
}

//Extract and sanitize the requested URL, handling cases where forms have been rewritten to point to the proxy.
if (isset($_POST["miniProxyFormAction"])) {
  $url = $_POST["miniProxyFormAction"];
  unset($_POST["miniProxyFormAction"]);
} else {
  $queryParams = Array();
  parse_str($_SERVER["QUERY_STRING"], $queryParams);
  //If the miniProxyFormAction field appears in the query string, make $url start with its value, and rebuild the the query string without it.
  if (isset($queryParams["miniProxyFormAction"])) {
    $formAction = $queryParams["miniProxyFormAction"];
    unset($queryParams["miniProxyFormAction"]);
    $url = $formAction . "?" . http_build_query($queryParams);
  } else {
    $url = substr($_SERVER["REQUEST_URI"], strlen($_SERVER["SCRIPT_NAME"]) + 1);
  }
}
if (empty($url)) {
    if (empty($startURL)) {
      die("<html>
    <!-- https://github.com/lizhongnian/miniProxy-embellish --!>
    <head>
        <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">
        <meta content=\"zh-CN\" http-equiv=\"Content-Language\">
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, user-scalable=no, minimal-ui\">
        <title>小小代理</title>
        <link rel=\"icon\" href=\"earth.png\">
        <style>
        * {
            padding:0;
            margin:0;
            box-sizing:border-box
        }
        html {
            -webkit-tap-highlight-color:transparent;
            height:100%;
            min-height:100%
        }
        body {
            min-height:100%;
            background-color:#FFF;
            -webkit-background-size:cover;
            -moz-background-size:cover;
            -o-background-size:cover;
            background-size:cover;
            max-width:100%;
            width:600px;
            margin:auto;
            text-align:center
        }
        #search_input {
            height:42px;
            width:95%;
            outline:0;
            border:none;
            font-size:15px;
            background-color:transparent;
            color:#6C6C6C
        }
        .search_part {
            margin-bottom:20px
        }
        span {
            display:block;
            overflow:hidden;
            padding-left:5px;
            vertical-align:middle
        }
        .box a {
            width:100%;
            height:100%;
            position:absolute;
            left:0;
            top:0
        }
        .hint {
            color:#8C8C8C;
            font-size:15px;
            word-wrap:break-word;
            overflow:auto;
            padding:50px 5px;
            text-align:center;
            margin:auto
        }
        .bookmark_part {
            margin:0 6%;
            padding:10px 0
        }
        .frosted-glass {
            background-color:rgba(0, 0, 0, 0);
            position:fixed;
            left:0;
            top:0;
            width:100%;
            height:100%;
            z-index:-999
        }
        .logo {
            font-size:28px;
            white-space:normal;
            word-wrap:break-word;
            text-decoration:none;
            color:#6C6C6C
        }
        .search.icon {
            color:#666;
            width:12px;
            height:12px;
            border:solid 2px currentColor;
            border-radius:100%;
            -webkit-transform:rotate(-45deg);
            transform:rotate(-45deg);
            text-align:center;
            margin:auto
        }
        .search.icon:before {
            content:'';
            position:absolute;
            top:10px;
            left:3px;
            height:5px;
            width:2px;
            background-color:currentColor
        }
        img.smaller {
            width:160px;
            max-width:86px;
            border-radius:50%;
            min-width:160px;
            height:160px;
            min-height:160px;
            object-fit:cover;
            max-height:50%
        }
        #content {
            position:absolute;
            top:5%;
            max-width:600px;
            width:100%
        }
        .search_bar {
            display:table;
            vertical-align:middle;
            width:90%;
            height:42px;
            max-width:600px;
            margin:0 auto;
            margin-top:15px;
            border:1px solid rgba(0, 0, 0, .1);
            border-radius:100px;
            background:#fff;
            box-shadow:0 0 2px rgba(255, 255, 255, .6)
        }
        #search_input {
            color:#6c6c6c
        }
        #search_submit {
            display:none;
            outline:0;
            height:42px;
            width:42px;
            float:right;
            color:#666;
            font-size:15px;
            font-weight:700;
            border:none;
            background-color:transparent;
            padding:0 10px 0 10px
        }
        .box {
            position:relative;
            display:inline-block;
            width:75px;
            border:0
        }
        .title {
            border-radius:100%;
            color:#fff;
            width:3.4em;
            line-height:3.4em;
            height:3.4em;
            font-size:15px;
            white-space:nowrap;
            overflow:hidden;
            margin:auto;
            text-overflow:ellipsis;
            -o-text-overflow:ellipsis;
            -ms-text-overflow:ellipsis
        }
        .url {
            padding:6px 0 4px;
            width:72px;
            color:#8C8C8C;
            font-size:11px;
            white-space:nowrap;
            overflow:hidden;
            margin:auto;
            text-overflow:ellipsis;
            -o-text-overflow:ellipsis;
            -ms-text-overflow:ellipsis
        }
        .bookmark_part {
            width:90%;
            max-width:600px;
            background-color:transparent;
            margin:0 auto;
            padding:0;
            border-radius:0
        }
        </style>
        <script src=\"https://cdn.staticfile.org/jquery/3.4.1/jquery.min.js\"></script>
    </head>
    <!-- https://github.com/lizhongnian/miniProxy-embellish --!>
    <body>
        <div class=\"frosted-glass\"></div>
        <div id=\"content\">
            <div class=\"search_part\">
                <a class=\"logo\" href=\"http://2fan.win\">
                    <img id=\"earth_image\" class=\"smaller\" src=\"earth.png\">
                </a>
                <form onsubmit=\"if (document.getElementById('site').value) { window.location.href='" . PROXY_PREFIX . "' + document.getElementById('site').value; return false; } else { window.location.href='" . PROXY_PREFIX . $landingExampleURL . "'; return false; }\" autocomplete=\"off\">
                    <input id=\"site\" type=\"text\" size=\"35\" />
                    <input type=\"submit\" value=\"GO！\" />
                </form>
            </div>
            <script type=\"text/javascript\">
            function showButton() {
                document.getElementById(\"search_submit\").style.display = \"block\";
            }
            function hideButton() {
                var key = document.getElementById(\"search_input\").value;
                if (key == \"\") {
                    document.getElementById(\"search_submit\").style.display = \"none\";
                }
            }
            function search() {
                var key = document.getElementById(\"search_input\").value;
                if (key != \"\") {
                    window.via.searchText(key);
                    document.getElementById(\"search_input\").value = \"\";
                }
                return false;
            }
            </script>
             <h2>欢迎使用在线代理程序</h2>
            <br/>它可以像这样直接调用网页代理:
            <br/> <a href=\"" . PROXY_PREFIX . $landingExampleURL . "\">" . PROXY_PREFIX . $landingExampleURL . "</a>
            <br/>
            <br/>当然，你也可以直接在上面输入链接进行代理
            <br/>
            <br/>魔法访问国外，仅供查询资料
            <br/>请勿非法使用，否则后果自负
            <br/><p class='m-b-0'>Copyright © 2019 七彩云demo | Create by <a href='https://www.7colorblog.com'>七彩blog</a></p>
            <br/>
        </div>
    </body>
</html>");
    } else {
      $url = $startURL;
    }
} else if (strpos($url, ":/") !== strpos($url, "://")) {
    //Work around the fact that some web servers (e.g. IIS 8.5) change double slashes appearing in the URL to a single slash.
    //See https://github.com/joshdick/miniProxy/pull/14
    $pos = strpos($url, ":/");
    $url = substr_replace($url, "://", $pos, strlen(":/"));
}
$scheme = parse_url($url, PHP_URL_SCHEME);
if (empty($scheme)) {
  //Assume that any supplied URLs starting with // are HTTP URLs.
  if (strpos($url, "//") === 0) {
    $url = "http:" . $url;
  }
} else if (!preg_match("/^https?$/i", $scheme)) {
    die('Error: Detected a "' . $scheme . '" URL. miniProxy exclusively supports http[s] URLs.');
}

//Validate the requested URL against the whitelist.
$urlIsValid = count($whitelistPatterns) === 0;
foreach ($whitelistPatterns as $pattern) {
  if (preg_match($pattern, $url)) {
    $urlIsValid = true;
    break;
  }
}
if (!$urlIsValid) {
  die("Error: The requested URL was disallowed by the server administrator.");
}

$response = makeRequest($url);
$rawResponseHeaders = $response["headers"];
$responseBody = $response["body"];
$responseInfo = $response["responseInfo"];

//If CURLOPT_FOLLOWLOCATION landed the proxy at a diferent URL than
//what was requested, explicitly redirect the proxy there.
$responseURL = $responseInfo["url"];
if ($responseURL !== $url) {
  header("Location: " . PROXY_PREFIX . $responseURL, true);
  exit(0);
}

//A regex that indicates which server response headers should be stripped out of the proxified response.
$header_blacklist_pattern = "/^Content-Length|^Transfer-Encoding|^Content-Encoding.*gzip/i";

//cURL can make multiple requests internally (for example, if CURLOPT_FOLLOWLOCATION is enabled), and reports
//headers for every request it makes. Only proxy the last set of received response headers,
//corresponding to the final request made by cURL for any given call to makeRequest().
$responseHeaderBlocks = array_filter(explode("\r\n\r\n", $rawResponseHeaders));
$lastHeaderBlock = end($responseHeaderBlocks);
$headerLines = explode("\r\n", $lastHeaderBlock);
foreach ($headerLines as $header) {
  $header = trim($header);
  if (!preg_match($header_blacklist_pattern, $header)) {
    header($header, false);
  }
}
//Prevent robots from indexing proxified pages
header("X-Robots-Tag: noindex, nofollow", true);

if ($forceCORS) {
  //This logic is based on code found at: http://stackoverflow.com/a/9866124/278810
  //CORS headers sent below may conflict with CORS headers from the original response,
  //so these headers are sent after the original response headers to ensure their values
  //are the ones that actually end up getting sent to the browser.
  //Explicit [ $replace = true ] is used for these headers even though this is PHP's default behavior.

  //Allow access from any origin.
  header("Access-Control-Allow-Origin: *", true);
  header("Access-Control-Allow-Credentials: true", true);

  //Handle CORS headers received during OPTIONS requests.
  if ($_SERVER["REQUEST_METHOD"] == "OPTIONS") {
    if (isset($_SERVER["HTTP_ACCESS_CONTROL_REQUEST_METHOD"])) {
      header("Access-Control-Allow-Methods: GET, POST, OPTIONS", true);
    }
    if (isset($_SERVER["HTTP_ACCESS_CONTROL_REQUEST_HEADERS"])) {
      header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}", true);
    }
    //No further action is needed for OPTIONS requests.
    exit(0);
  }

}

$contentType = "";
if (isset($responseInfo["content_type"])) $contentType = $responseInfo["content_type"];

//This is presumably a web page, so attempt to proxify the DOM.
if (stripos($contentType, "text/html") !== false) {

  //Attempt to normalize character encoding.
  $detectedEncoding = mb_detect_encoding($responseBody, "UTF-8, ISO-8859-1");
  if ($detectedEncoding) {
    $responseBody = mb_convert_encoding($responseBody, "HTML-ENTITIES", $detectedEncoding);
  }

  //Parse the DOM.
  $doc = new DomDocument();
  @$doc->loadHTML($responseBody);
  $xpath = new DOMXPath($doc);

  //Rewrite forms so that their actions point back to the proxy.
  foreach($xpath->query("//form") as $form) {
    $method = $form->getAttribute("method");
    $action = $form->getAttribute("action");
    //If the form doesn't have an action, the action is the page itself.
    //Otherwise, change an existing action to an absolute version.
    $action = empty($action) ? $url : rel2abs($action, $url);
    //Rewrite the form action to point back at the proxy.
    $form->setAttribute("action", rtrim(PROXY_PREFIX, "?"));
    //Add a hidden form field that the proxy can later use to retreive the original form action.
    $actionInput = $doc->createDocumentFragment();
    $actionInput->appendXML('<input type="hidden" name="miniProxyFormAction" value="' . htmlspecialchars($action) . '" />');
    $form->appendChild($actionInput);
  }
  //Proxify <meta> tags with an 'http-equiv="refresh"' attribute.
  foreach ($xpath->query("//meta[@http-equiv]") as $element) {
    if (strcasecmp($element->getAttribute("http-equiv"), "refresh") === 0) {
      $content = $element->getAttribute("content");
      if (!empty($content)) {
        $splitContent = preg_split("/=/", $content);
        if (isset($splitContent[1])) {
          $element->setAttribute("content", $splitContent[0] . "=" . PROXY_PREFIX . rel2abs($splitContent[1], $url));
        }
      }
    }
  }
  //Profixy <style> tags.
  foreach($xpath->query("//style") as $style) {
    $style->nodeValue = proxifyCSS($style->nodeValue, $url);
  }
  //Proxify tags with a "style" attribute.
  foreach ($xpath->query("//*[@style]") as $element) {
    $element->setAttribute("style", proxifyCSS($element->getAttribute("style"), $url));
  }
  //Proxify "srcset" attributes in <img> tags.
  foreach ($xpath->query("//img[@srcset]") as $element) {
    $element->setAttribute("srcset", proxifySrcset($element->getAttribute("srcset"), $url));
  }
  //Proxify any of these attributes appearing in any tag.
  $proxifyAttributes = array("href", "src");
  foreach($proxifyAttributes as $attrName) {
    foreach($xpath->query("//*[@" . $attrName . "]") as $element) { //For every element with the given attribute...
      $attrContent = $element->getAttribute($attrName);
      if ($attrName == "href" && preg_match("/^(about|javascript|magnet|mailto):|#/i", $attrContent)) continue;
      if ($attrName == "src" && preg_match("/^(data):/i", $attrContent)) continue;
      $attrContent = rel2abs($attrContent, $url);
      $attrContent = PROXY_PREFIX . $attrContent;
      $element->setAttribute($attrName, $attrContent);
    }
  }

  //Attempt to force AJAX requests to be made through the proxy by
  //wrapping window.XMLHttpRequest.prototype.open in order to make
  //all request URLs absolute and point back to the proxy.
  //The rel2abs() JavaScript function serves the same purpose as the server-side one in this file,
  //but is used in the browser to ensure all AJAX request URLs are absolute and not relative.
  //Uses code from these sources:
  //http://stackoverflow.com/questions/7775767/javascript-overriding-xmlhttprequest-open
  //https://gist.github.com/1088850
  //TODO: This is obviously only useful for browsers that use XMLHttpRequest but
  //it's better than nothing.

  $head = $xpath->query("//head")->item(0);
  $body = $xpath->query("//body")->item(0);
  $prependElem = $head != NULL ? $head : $body;

  //Only bother trying to apply this hack if the DOM has a <head> or <body> element;
  //insert some JavaScript at the top of whichever is available first.
  //Protects against cases where the server sends a Content-Type of "text/html" when
  //what's coming back is most likely not actually HTML.
  //TODO: Do this check before attempting to do any sort of DOM parsing?
  if ($prependElem != NULL) {

    $scriptElem = $doc->createElement("script",
      '(function() {

        if (window.XMLHttpRequest) {

          function parseURI(url) {
            var m = String(url).replace(/^\s+|\s+$/g, "").match(/^([^:\/?#]+:)?(\/\/(?:[^:@]*(?::[^:@]*)?@)?(([^:\/?#]*)(?::(\d*))?))?([^?#]*)(\?[^#]*)?(#[\s\S]*)?/);
            // authority = "//" + user + ":" + pass "@" + hostname + ":" port
            return (m ? {
              href : m[0] || "",
              protocol : m[1] || "",
              authority: m[2] || "",
              host : m[3] || "",
              hostname : m[4] || "",
              port : m[5] || "",
              pathname : m[6] || "",
              search : m[7] || "",
              hash : m[8] || ""
            } : null);
          }

          function rel2abs(base, href) { // RFC 3986

            function removeDotSegments(input) {
              var output = [];
              input.replace(/^(\.\.?(\/|$))+/, "")
                .replace(/\/(\.(\/|$))+/g, "/")
                .replace(/\/\.\.$/, "/../")
                .replace(/\/?[^\/]*/g, function (p) {
                  if (p === "/..") {
                    output.pop();
                  } else {
                    output.push(p);
                  }
                });
              return output.join("").replace(/^\//, input.charAt(0) === "/" ? "/" : "");
            }

            href = parseURI(href || "");
            base = parseURI(base || "");

            return !href || !base ? null : (href.protocol || base.protocol) +
            (href.protocol || href.authority ? href.authority : base.authority) +
            removeDotSegments(href.protocol || href.authority || href.pathname.charAt(0) === "/" ? href.pathname : (href.pathname ? ((base.authority && !base.pathname ? "/" : "") + base.pathname.slice(0, base.pathname.lastIndexOf("/") + 1) + href.pathname) : base.pathname)) +
            (href.protocol || href.authority || href.pathname ? href.search : (href.search || base.search)) +
            href.hash;

          }

          var proxied = window.XMLHttpRequest.prototype.open;
          window.XMLHttpRequest.prototype.open = function() {
              if (arguments[1] !== null && arguments[1] !== undefined) {
                var url = arguments[1];
                url = rel2abs("' . $url . '", url);
                if (url.indexOf("' . PROXY_PREFIX . '") == -1) {
                  url = "' . PROXY_PREFIX . '" + url;
                }
                arguments[1] = url;
              }
              return proxied.apply(this, [].slice.call(arguments));
          };

        }

      })();'
    );
    $scriptElem->setAttribute("type", "text/javascript");

    $prependElem->insertBefore($scriptElem, $prependElem->firstChild);

  }

  echo "<!-- Proxified page constructed by miniProxy -->\n" . $doc->saveHTML();
} else if (stripos($contentType, "text/css") !== false) { //This is CSS, so proxify url() references.
  echo proxifyCSS($responseBody, $url);
} else { //This isn't a web page or CSS, so serve unmodified through the proxy with the correct headers (images, JavaScript, etc.)
  header("Content-Length: " . strlen($responseBody), true);
  echo $responseBody;
}
