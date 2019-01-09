=== MultiLogin ===
Contributors: dougwollison
Tags: Cross-Domain login solution for multisite installations.
Requires at least: 4.5
Tested up to: 5.0.2
Stable tag: 1.0.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Cross-Domain login solution for multisite installations.

== Description ==

MultiLogin allows you to log into your network once and be authenticated on all domains in it.

Normally, when logging into a network site, you're only authenticated on that domain and it's
subdomains. When you try to access the admin for another site on your network with a different
domain, you'll have to log in on that one separately. This plugin generates login tokens which
authenticate you in the background on other sites once you successfully log in on one.

== Installation ==

1. Upload the contents of `multilogin.tar.gz` to your `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Log out and back in to be authenticated on all your sites!

== Changelog ==

**Details on each release can be found [on the GitHub releases page](https://github.com/dougwollison/multilogin/releases) for this project.**

= 1.0.0 =
Initial public release.
