
import "vt"

rule VT_HTML_URL_MAL_Stealer_Login_Panels_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects Potentially New Stealer Login Panels"
    target_entity = "url"
  
  strings:
    $stealer = "stealer"

  condition:
    vt.net.url.new_url 
    and vt.net.url.path icontains "/login"
    and (vt.net.url.html_title icontains "stealer" or $stealer)
}

