
import "vt"

rule url_template
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

