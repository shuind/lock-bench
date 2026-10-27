"""Check report links and summary downloads without depending on local raw results."""

import base64
from html.parser import HTMLParser
import json
from pathlib import Path


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.anchors = set()
        self.tables = 0
        self.downloads = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        identifier = attrs.get('id')
        if identifier:
            if identifier in self.ids:
                raise ValueError('Duplicate report ID: ' + identifier)
            self.ids.add(identifier)
        if tag == 'table':
            self.tables += 1
        href = attrs.get('href', '')
        if href.startswith('#') and len(href) > 1:
            self.anchors.add(href[1:])
        prefix = 'data:application/json;base64,'
        if href.startswith(prefix):
            summary = json.loads(base64.b64decode(href[len(prefix) :], validate=True))
            if summary.get('schema_version') != 1:
                raise ValueError('Invalid summary download')
            self.downloads += 1


def verify_report(path):
    markup = Path(path).read_text(encoding='utf-8')
    parser = ReportParser()
    parser.feed(markup)
    parser.close()
    if not parser.tables:
        raise ValueError('Report has no results table')
    missing = parser.anchors - parser.ids
    if missing:
        raise ValueError('Missing report anchors: ' + ', '.join(sorted(missing)))
    if 'report-data' in parser.ids or 'download-json' in parser.ids:
        raise ValueError('Report still embeds legacy raw-data downloads')
    print(f'PASS: {parser.tables} report tables, anchors and {parser.downloads} summary downloads')


if __name__ == '__main__':
    verify_report(Path(__file__).resolve().parents[2] / 'docs/REPORT.html')
