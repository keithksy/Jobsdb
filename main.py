def parser():
	search_keywords = ['python','data engineer']
	for keyword in search_keywords:
		if len(keyword) > 1:
			keyword = '-'.join(keyword.split(' '))
		init_url = 'https://hk.jobsdb.com/hk/search-jobs/' + keyword + '/1?sort=createdAt'
		rawdata = request_page(init_url)
		html = HTMLParser(rawdata['html'])
		fpages = html.css_first("span[class='z1s6m00 _1hbhsw64y y44q7i0 y44q7i1 y44q7i21 _1d0g9qk4 y44q7i7']")
		total_jobs = fpages.text().split('of')[1].split('jobs')[0].replace(',','').strip()
		jobs_per_page = 30
		total_pages = math.ceil(int(total_jobs)/jobs_per_page)

		for page in range(total_pages)[:2]:
			url = 'https://hk.jobsdb.com/hk/search-jobs/' + keyword + '/'+ str(page+1) + '?sort=createdAt'
			page_data = request_page(url)
			data = HTMLParser(page_data['html'])
			page_jobs = data.css("div[class='z1s6m00 _1hbhsw67i _1hbhsw66e _1hbhsw69q _1hbhsw68m _1hbhsw6n _1hbhsw65a _1hbhsw6ga _1hbhsw6fy']")
			for job_info in page_jobs[:5]:
				info = job_info.css_first("h1[class='z1s6m00 _1hbhsw64y y44q7i0 y44q7i3 y44q7i21 y44q7ii']")
				url_prefix = 'https://hk.jobsdb.com'
				url_suffix = info.css_first('a').attrs['href']
				url = url_prefix + url_suffix
				title = info.text()
				company_name = job_info.css_first("span[class='z1s6m00 _1hbhsw64y y44q7i0 y44q7i1 y44q7i21 y44q7ih']").text()
				

            for job in alldata:
            if 'data' in job['title'].lower():
                print(job)

        details = request_page(job['url'])
        data = HTMLParser(details['html'])
        data.css_first("div[data-automation='jobDescription']").html#.attributes#.css('p'))
	    d = {"company": company_name, "title":title, "url":url}
        alldata.append(d)