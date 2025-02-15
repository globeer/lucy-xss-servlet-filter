/*
 * Copyright 2014 NAVER Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.navercorp.lucy.security.xss.servletfilter;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;

import org.hamcrest.MatcherAssert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.navercorp.lucy.security.xss.servletfilter.defender.XssFilterDefender;
import com.navercorp.lucy.security.xss.servletfilter.defender.XssPreventerDefender;
import com.navercorp.lucy.security.xss.servletfilter.defender.XssSaxFilterDefender;

/**
 * @author todtod80
 * @author leeplay
 * @author benelog
 */
public class XssEscapeFilterConfigTest {
	static XssEscapeFilterConfig config;
	
	@BeforeClass
	public static void init() throws Exception {
		config = new XssEscapeFilterConfig();
	}

	@Test(expected = IllegalStateException.class)
	public void testWhenNotExistingConfigFile() {
		new XssEscapeFilterConfig("unkonwn-file.xml");
	}

	@Test(expected = IllegalStateException.class)
	public void testWhenUnknownDefnderClass() {
		new XssEscapeFilterConfig("lucy-xss-servlet-filter-rule-unknown-class.xml");
	}

	@Test
	public void testWhenEmptyDefnderName() {
		new XssEscapeFilterConfig("lucy-xss-servlet-filter-rule-empty-name.xml");
		// leaves warning message
	}

	@Test
	public void testGetDefaultDefender() {
		MatcherAssert.assertThat(config.getDefaultDefender(), instanceOf(XssPreventerDefender.class));
	}

	@Test
	public void testGetDefenderMap() {
		MatcherAssert.assertThat(config.getDefenderMap().size(), is(3));
		MatcherAssert.assertThat(config.getDefenderMap().get("xssPreventerDefender"), instanceOf(XssPreventerDefender.class));
		MatcherAssert.assertThat(config.getDefenderMap().get("xssFilterDefender"), instanceOf(XssFilterDefender.class));
		MatcherAssert.assertThat(config.getDefenderMap().get("xssSaxFilterDefender"), instanceOf(XssSaxFilterDefender.class));
	}
	
	@Test
	public void testGetGlobalUrlParamRule() {
		MatcherAssert.assertThat(config.getUrlParamRule("/notExistUrl.do", "globalParameter"), instanceOf(XssEscapeFilterRule.class));
		MatcherAssert.assertThat(config.getUrlParamRule("/notExistUrl.do", "globalParameter").isUseDefender(), is(false));
		MatcherAssert.assertThat(config.getUrlParamRule("/notExistUrl.do", "globalParameter").getDefender(), is(config.getDefaultDefender()));
	}
	
	@Test
	public void testGetUrlParamRule() {
		MatcherAssert.assertThat(config.getUrlParamRule("/url1.do", "title"), is(nullValue()));
		MatcherAssert.assertThat(config.getUrlParamRule("/url1.do", "url1Parameter"), instanceOf(XssEscapeFilterRule.class));
		MatcherAssert.assertThat(config.getUrlParamRule("/url1.do", "url1Parameter").isUseDefender(), is(false));
		MatcherAssert.assertThat(config.getUrlParamRule("/url1.do", "url1Parameter").getDefender(), is(config.getDefaultDefender()));
		
		MatcherAssert.assertThat(config.getUrlParamRule("/url2.do", "url2Parameter3"), instanceOf(XssEscapeFilterRule.class));
		MatcherAssert.assertThat(config.getUrlParamRule("/url2.do", "url2Parameter3").isUseDefender(), is(true));
		MatcherAssert.assertThat(config.getUrlParamRule("/url2.do", "url2Parameter3").getDefender(), is(config.getDefenderMap().get("xssPreventerDefender")));

		MatcherAssert.assertThat(config.getUrlParamRule("/url2.do", "url2Parameter2"), instanceOf(XssEscapeFilterRule.class));
		MatcherAssert.assertThat(config.getUrlParamRule("/url2.do", "url2Parameter2").isUseDefender(), is(true));
		MatcherAssert.assertThat(config.getUrlParamRule("/url2.do", "url2Parameter2").getDefender(), is(config.getDefenderMap().get("xssSaxFilterDefender")));
	}
	
	@Test
	public void testUrlDisableAndPrefix() {
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl1.do", null).isUseDefender(), is(false));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl2.do", null), is(nullValue()));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl3.do", "query").isUseDefender(), is(false));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "query").isUseDefender(), is(false));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "prefix1").isUseDefender(), is(true));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "prefix1aaaa").isUseDefender(), is(true));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "prefix2aaaa"), is(nullValue()));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "prefix2").isUseDefender(), is(false));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "prefix3").isUseDefender(), is(true));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "prefix3aaaa").isUseDefender(), is(true));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "prefix4").isUseDefender(), is(false));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "prefix4aaaa").isUseDefender(), is(false));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "prefix5aaaa"),  is(nullValue()));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "prefix5").isUseDefender(), is(true));
		MatcherAssert.assertThat(config.getUrlParamRule("/disableUrl4.do", "prefix6aaaa").getDefender(), instanceOf(XssSaxFilterDefender.class));
	}
}
