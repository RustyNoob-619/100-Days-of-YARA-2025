
import "vt"

rule VT_HTML_URL_MAL_Stealer_Medusa_Panel_FEB25
{
  meta:
    author = "RustyNoob619"
    description = "Detects Medusa Stealer C2 Panel based on the Favicon"
    target_entity = "url"

  condition:
    vt.net.url.new_url 
    and vt.net.url.favicon.dhash == "69d49496f4711796"
}
