# Customized Job Searching Engine
## Highlights
- Implements web-scraping for the HKJobsDB website
- Provides a customizable filter for job title searches
- Supports multiple keywords searches
- Docker Containerized for easy-access

## Guide
### Prerequisites
- Docker installed
- Git cloned to your local environment

### Get started
1. Update the keyword for searching in Dockerfile
```
E.g.
CMD ["python3", "main.py", "--get_jobs", "--keywords", "python"]
CMD ["python3", "main.py", "--get_jobs", "--keywords", "data-engineer", "data-analyst"]
```

2. Build the docker image
```
docker build -t test .
```

3. Create container from image and run
```
docker run test
```

## Latest Update
2024/12/28:
⚠️ Jobsdb has changed their css, parser not longer available
