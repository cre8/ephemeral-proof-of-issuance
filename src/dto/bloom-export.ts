export interface BloomExport {
  type: 'BloomFilter';
  _size: number;
  _nbHashes: number;
  _filter: {
    size: number;
    content: string;
  };
  // seed is always 78187493520 if not changed https://www.npmjs.com/package/bloom-filters#export-and-import
  _seed: number;
}
