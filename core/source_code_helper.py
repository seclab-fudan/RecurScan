import logging
import os
import time

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from config import GIT_REPOSITORY_TO_ACCOUNT_MAP, SOURCE_CODE_PATH

logger = logging.getLogger(__name__)
chrome_options = Options()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--disable-gpu')


class SourceCodeHelper(object):
    def __init__(self, delay=1, init_driver=False):
        self.delay = delay
        if init_driver:
            self.driver = webdriver.Chrome(options=chrome_options)
        else:
            self.driver = None
        self.download_backend = "requests"

    def __init_driver(self):
        self.driver = webdriver.Chrome()

    def __del__(self):
        if self.driver is not None:
            self.driver.close()

    @staticmethod
    def _get_git_source_code_url(git_account, git_repository, version, file_path):
        git_url_format = "https://raw.githubusercontent.com/{git_account}/{git_repository}/{version}/{file_path}"
        return git_url_format.format(
                git_account=git_account,
                git_repository=git_repository,
                version=version,
                file_path=file_path,
        )

    def download_source(self, git_repository, version, file_name, CMS_SOURCE_CODE_PATH=SOURCE_CODE_PATH,
                        git_account=None):
        download_path = os.path.join(
                CMS_SOURCE_CODE_PATH, git_repository, version, file_name
        )
        if os.path.exists(
                download_path
        ):
            return download_path
        elif os.path.exists(
                download_path + ".no.file"
        ):
            return download_path
        else:
            if git_account is None:
                git_account = GIT_REPOSITORY_TO_ACCOUNT_MAP[git_repository]
            download_url = SourceCodeHelper._get_git_source_code_url(
                    git_account=git_account,
                    git_repository=git_repository,
                    version=version,
                    file_path=file_name
            )
            if self.download_backend == "selenium":
                if self.driver is None:
                    self.driver = webdriver.Chrome(options=chrome_options)
                self.driver.get(download_url)
                if not os.path.exists(os.path.split(download_path)[0]):
                    os.makedirs(os.path.split(download_path)[0])
                try:
                    buffer = self.driver.find_element_by_xpath('/html/body/pre').text
                    if buffer == "404: Not Found":
                        open(download_path + ".no.file", 'w', encoding='utf8').write("")
                    else:
                        open(download_path, 'w', encoding='utf8').write(buffer)
                except Exception as e:
                    logger.fatal(e)
                    logger.warning("Use backend requests failed , please change download_backend to `requests`")

            elif self.download_backend == "requests":
                if not os.path.exists(os.path.split(download_path)[0]):
                    os.makedirs(os.path.split(download_path)[0])
                try:
                    buffer = requests.get(url=download_url, verify=False).text
                    if buffer == "404: Not Found":
                        open(download_path + ".no.file", 'w', encoding='utf8').write("")
                    else:
                        open(download_path, 'w', encoding='utf8').write(buffer)
                except Exception as e:
                    logger.fatal(e)
                    logger.warning("Use backend requests failed , please change download_backend to `selenium`")

            else:
                raise NotImplemented(f"Not implement download_backend {self.download_backend}")
        time.sleep(self.delay)
        return download_path
