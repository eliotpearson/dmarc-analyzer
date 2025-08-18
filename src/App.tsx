import React, { useState, useRef } from 'react';
import { Upload, FileText, AlertCircle, CheckCircle, XCircle, Info, Shield, Mail, BarChart3 } from 'lucide-react';

interface Record {
  sourceIp: string;
  count: number;
  disposition: string;
  dkimResult: string;
  spfResult: string;
  headerFrom: string;
  dkimDomain?: string;
  spfDomain?: string;
  dmarcResult: 'pass' | 'fail';
  dkimAligned: boolean;
  spfAligned: boolean;
  reasons: string[];
}

interface PolicyInfo {
  domain: string;
  p: string;
  sp: string;
  adkim: string;
  aspf: string;
}

interface ReportMetadata {
  orgName: string;
  reportId: string;
  beginTime: string;
  endTime: string;
}

interface Summary {
  total: number;
  pass: number;
  fail: number;
  quarantine: number;
  reject: number;
}

function App() {
  const [isProcessing, setIsProcessing] = useState(false);
  const [statusMessage, setStatusMessage] = useState('');
  const [statusType, setStatusType] = useState<'info' | 'success' | 'error'>('info');
  const [reportData, setReportData] = useState<{
    metadata: ReportMetadata;
    policy: PolicyInfo;
    records: Record[];
    summary: Summary;
  } | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const showStatus = (message: string, type: 'info' | 'success' | 'error' = 'info') => {
    setStatusMessage(message);
    setStatusType(type);
  };

  const getTagContent = (parent: Element, tag: string): string => {
    const element = parent.getElementsByTagName(tag)[0];
    return element ? element.textContent || 'N/A' : 'N/A';
  };

  const checkAlignment = (headerFromDomain: string, authDomain: string, alignmentMode: string): boolean => {
    if (alignmentMode === 's') {
      // Strict alignment - exact match required
      return headerFromDomain.toLowerCase() === authDomain.toLowerCase();
    } else {
      // Relaxed alignment - subdomain allowed
      const headerDomain = headerFromDomain.toLowerCase();
      const authDom = authDomain.toLowerCase();
      return headerDomain === authDom || headerDomain.endsWith('.' + authDom);
    }
  };

  const processRecord = (record: Element, policy: PolicyInfo): Record => {
    const row = record.getElementsByTagName('row')[0];
    const sourceIp = getTagContent(row, 'source_ip');
    const count = parseInt(getTagContent(row, 'count'), 10);
    const disposition = getTagContent(row, 'disposition');

    const identifiers = record.getElementsByTagName('identifiers')[0];
    const headerFrom = getTagContent(identifiers, 'header_from');

    const authResults = record.getElementsByTagName('auth_results')[0];
    const dkimElements = authResults.getElementsByTagName('dkim');
    const spfElements = authResults.getElementsByTagName('spf');

    let dkimResult = 'none';
    let dkimDomain = '';
    let dkimAligned = false;

    if (dkimElements.length > 0) {
      dkimResult = getTagContent(dkimElements[0], 'result');
      dkimDomain = getTagContent(dkimElements[0], 'domain');
      if (dkimResult === 'pass') {
        dkimAligned = checkAlignment(headerFrom, dkimDomain, policy.adkim);
      }
    }

    let spfResult = 'none';
    let spfDomain = '';
    let spfAligned = false;

    if (spfElements.length > 0) {
      spfResult = getTagContent(spfElements[0], 'result');
      spfDomain = getTagContent(spfElements[0], 'domain');
      if (spfResult === 'pass') {
        spfAligned = checkAlignment(headerFrom, spfDomain, policy.aspf);
      }
    }

    // DMARC passes if at least one authentication method passes AND aligns
    const dmarcResult: 'pass' | 'fail' = (dkimResult === 'pass' && dkimAligned) || (spfResult === 'pass' && spfAligned) ? 'pass' : 'fail';

    const reasons: string[] = [];
    if (dmarcResult === 'fail') {
      if (dkimResult !== 'pass' && spfResult !== 'pass') {
        reasons.push('Neither DKIM nor SPF passed authentication');
      } else if (dkimResult === 'pass' && !dkimAligned && spfResult === 'pass' && !spfAligned) {
        reasons.push('Both DKIM and SPF failed alignment checks');
      } else if (dkimResult === 'pass' && !dkimAligned) {
        reasons.push('DKIM passed but failed alignment check');
      } else if (spfResult === 'pass' && !spfAligned) {
        reasons.push('SPF passed but failed alignment check');
      }
    }

    return {
      sourceIp,
      count,
      disposition,
      dkimResult,
      spfResult,
      headerFrom,
      dkimDomain,
      spfDomain,
      dmarcResult,
      dkimAligned,
      spfAligned,
      reasons
    };
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsProcessing(true);
    setReportData(null);
    showStatus('Processing file, please wait...', 'info');

    try {
      const arrayBuffer = await file.arrayBuffer();
      let xmlContent: string;

      if (file.name.endsWith('.gz')) {
        // @ts-ignore - pako is loaded via CDN
        xmlContent = pako.ungzip(new Uint8Array(arrayBuffer), { to: 'string' });
      } else if (file.name.endsWith('.zip')) {
        // @ts-ignore - JSZip is loaded via CDN
        const zip = new JSZip();
        const zipContent = await zip.loadAsync(arrayBuffer);
        const xmlFile = Object.values(zipContent.files).find((f: any) => f.name.toLowerCase().endsWith('.xml'));
        
        if (!xmlFile) {
          throw new Error('No XML file found inside the zip archive.');
        }
        xmlContent = await (xmlFile as any).async('string');
      } else {
        throw new Error('Unsupported file type. Please upload a .gz or .zip file.');
      }

      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(xmlContent, 'application/xml');

      if (xmlDoc.getElementsByTagName('parsererror').length) {
        throw new Error('Failed to parse XML from the file.');
      }

      // Extract metadata
      const reportMetadata = xmlDoc.getElementsByTagName('report_metadata')[0];
      const metadata: ReportMetadata = {
        orgName: getTagContent(reportMetadata, 'org_name'),
        reportId: getTagContent(reportMetadata, 'report_id'),
        beginTime: new Date(parseInt(getTagContent(reportMetadata, 'begin_date'), 10) * 1000).toLocaleDateString('en-US', { 
          year: 'numeric', 
          month: 'long', 
          day: 'numeric',
          timeZone: 'UTC'
        }),
        endTime: new Date(parseInt(getTagContent(reportMetadata, 'end_date'), 10) * 1000).toLocaleDateString('en-US', { 
          year: 'numeric', 
          month: 'long', 
          day: 'numeric',
          timeZone: 'UTC'
        })
      };

      // Extract policy
      const policyPublished = xmlDoc.getElementsByTagName('policy_published')[0];
      const policy: PolicyInfo = {
        domain: getTagContent(policyPublished, 'domain'),
        p: getTagContent(policyPublished, 'p'),
        sp: getTagContent(policyPublished, 'sp'),
        adkim: getTagContent(policyPublished, 'adkim') || 'r',
        aspf: getTagContent(policyPublished, 'aspf') || 'r'
      };

      // Process records
      const recordElements = xmlDoc.getElementsByTagName('record');
      const records: Record[] = [];
      const summary: Summary = { total: 0, pass: 0, fail: 0, quarantine: 0, reject: 0 };

      for (let i = 0; i < recordElements.length; i++) {
        const processedRecord = processRecord(recordElements[i], policy);
        records.push(processedRecord);

        summary.total += processedRecord.count;
        if (processedRecord.dmarcResult === 'pass') {
          summary.pass += processedRecord.count;
        } else {
          summary.fail += processedRecord.count;
        }
        
        if (processedRecord.disposition === 'quarantine') {
          summary.quarantine += processedRecord.count;
        } else if (processedRecord.disposition === 'reject') {
          summary.reject += processedRecord.count;
        }
      }

      setReportData({ metadata, policy, records, summary });
      showStatus('Report processed successfully!', 'success');

    } catch (error) {
      console.error('Processing error:', error);
      showStatus(`Error: ${(error as Error).message}`, 'error');
    } finally {
      setIsProcessing(false);
    }
  };

  const StatusIcon = ({ type }: { type: 'info' | 'success' | 'error' }) => {
    switch (type) {
      case 'success': return <CheckCircle className="w-5 h-5" />;
      case 'error': return <XCircle className="w-5 h-5" />;
      default: return <Info className="w-5 h-5" />;
    }
  };

  const getAlignmentText = (mode: string): string => {
    return mode === 's' ? 'Strict' : 'Relaxed';
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="border-b border-gray-800 bg-gray-900/95 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-indigo-400" />
              <h1 className="text-xl font-semibold text-white">DMARC Analyzer</h1>
            </div>
            <div className="flex items-center space-x-6 text-sm text-gray-300">
              <span className="flex items-center space-x-2">
                <Mail className="w-4 h-4" />
                <span>Email Security</span>
              </span>
              <span className="flex items-center space-x-2">
                <BarChart3 className="w-4 h-4" />
                <span>Analytics</span>
              </span>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <h2 className="text-4xl font-bold text-white mb-4">
            Analyze Your Email
            <span className="text-indigo-400 block">Authentication Reports</span>
          </h2>
          <p className="text-xl text-gray-400 max-w-2xl mx-auto">
            Upload compressed DMARC reports to get detailed insights into your email authentication performance and security posture.
          </p>
        </div>

        {/* Upload Section */}
        <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-2xl p-8 mb-8">
          <div className="max-w-2xl mx-auto">
            <label className="block text-sm font-medium text-gray-300 mb-4">
              Upload DMARC Report (.gz or .zip)
            </label>
            <div className="flex items-center justify-center w-full">
              <label className="flex flex-col items-center justify-center w-full h-40 border-2 border-gray-600 border-dashed rounded-xl cursor-pointer bg-gray-800/30 hover:bg-gray-700/30 transition-all duration-200">
                <div className="flex flex-col items-center justify-center pt-5 pb-6">
                  <Upload className="w-12 h-12 mb-4 text-indigo-400" />
                  <p className="mb-2 text-sm text-gray-300">
                    <span className="font-semibold">Click to upload</span> or drag and drop
                  </p>
                  <p className="text-xs text-gray-500">DMARC aggregate reports (.gz or .zip files)</p>
                </div>
                <input 
                  ref={fileInputRef}
                  type="file" 
                  className="hidden" 
                  accept=".gz,.zip"
                  onChange={handleFileUpload}
                  disabled={isProcessing}
                />
              </label>
            </div>
          </div>
        </div>

        {/* Status Message */}
        {statusMessage && (
          <div className={`flex items-center gap-3 p-4 rounded-xl mb-8 border ${
            statusType === 'error' ? 'bg-red-900/20 text-red-300 border-red-800/50' :
            statusType === 'success' ? 'bg-green-900/20 text-green-300 border-green-800/50' :
            'bg-blue-900/20 text-blue-300 border-blue-800/50'
          }`}>
            <StatusIcon type={statusType} />
            <span>{statusMessage}</span>
          </div>
        )}

        {/* Processing Indicator */}
        {isProcessing && (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-400"></div>
            <span className="ml-3 text-gray-400">Processing report...</span>
          </div>
        )}

        {/* Results */}
        {reportData && (
          <div className="space-y-8">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Report Info */}
              <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Report Details</h3>
                <div className="space-y-3">
                  <div>
                    <p className="text-sm text-gray-400">Organization</p>
                    <p className="text-white font-medium">{reportData.metadata.orgName}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Date Range</p>
                    <p className="text-white font-medium text-sm">{reportData.metadata.beginTime} → {reportData.metadata.endTime}</p>
                  </div>
                </div>
              </div>

              {/* Policy Info */}
              <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Domain Policy</h3>
                <div className="space-y-3">
                  <div>
                    <p className="text-sm text-gray-400">Domain</p>
                    <p className="text-white font-medium">{reportData.policy.domain}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Policy Action</p>
                    <p className="text-white font-medium uppercase">{reportData.policy.p}</p>
                  </div>
                </div>
              </div>

              {/* Summary Stats */}
              <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Email Summary</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center">
                    <p className="text-2xl font-bold text-green-400">{reportData.summary.pass}</p>
                    <p className="text-xs text-gray-400">Passed</p>
                  </div>
                  <div className="text-center">
                    <p className="text-2xl font-bold text-red-400">{reportData.summary.fail}</p>
                    <p className="text-xs text-gray-400">Failed</p>
                  </div>
                  <div className="text-center">
                    <p className="text-lg font-bold text-orange-400">{reportData.summary.quarantine}</p>
                    <p className="text-xs text-gray-400">Quarantined</p>
                  </div>
                  <div className="text-center">
                    <p className="text-lg font-bold text-red-500">{reportData.summary.reject}</p>
                    <p className="text-xs text-gray-400">Rejected</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Detailed Records */}
            <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-white mb-6">Authentication Results</h3>
              <div className="space-y-4">
                {reportData.records.map((record, index) => (
                  <div key={index} className="bg-gray-900/50 border border-gray-700 rounded-lg p-6">
                    <div className="flex items-center justify-between mb-4">
                      <h4 className="text-lg font-medium text-white">
                        Record #{index + 1}
                        <span className="text-sm font-normal text-gray-400 ml-2">
                          ({record.count} {record.count === 1 ? 'email' : 'emails'})
                        </span>
                      </h4>
                      <div className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium ${
                        record.dmarcResult === 'pass' 
                          ? 'bg-green-900/30 text-green-300 border border-green-800/50' 
                          : 'bg-red-900/30 text-red-300 border border-red-800/50'
                      }`}>
                        {record.dmarcResult === 'pass' ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                        DMARC {record.dmarcResult.toUpperCase()}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <div>
                        <h5 className="text-sm font-medium text-gray-300 mb-3">Email Details</h5>
                        <div className="space-y-2 text-sm">
                          <div className="flex justify-between">
                            <span className="text-gray-400">Source IP:</span>
                            <span className="font-mono text-gray-200">{record.sourceIp}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Header From:</span>
                            <span className="font-mono text-gray-200">{record.headerFrom}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Disposition:</span>
                            <span className={`font-medium ${
                              record.disposition === 'none' ? 'text-gray-300' :
                              record.disposition === 'quarantine' ? 'text-orange-400' :
                              'text-red-400'
                            }`}>
                              {record.disposition}
                            </span>
                          </div>
                        </div>
                      </div>

                      <div>
                        <h5 className="text-sm font-medium text-gray-300 mb-3">Authentication Status</h5>
                        <div className="space-y-3">
                          {/* DKIM Result */}
                          <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                            <div>
                              <p className="text-sm font-medium text-gray-200">DKIM</p>
                              <p className="text-xs text-gray-400">Domain: {record.dkimDomain || 'N/A'}</p>
                            </div>
                            <div className="text-right">
                              <div className={`text-sm font-medium ${
                                record.dkimResult === 'pass' ? 'text-green-400' : 'text-red-400'
                              }`}>
                                {record.dkimResult.toUpperCase()}
                              </div>
                              {record.dkimResult === 'pass' && (
                                <div className={`text-xs ${
                                  record.dkimAligned ? 'text-green-400' : 'text-red-400'
                                }`}>
                                  {record.dkimAligned ? 'Aligned' : 'Not Aligned'}
                                </div>
                              )}
                            </div>
                          </div>

                          {/* SPF Result */}
                          <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                            <div>
                              <p className="text-sm font-medium text-gray-200">SPF</p>
                              <p className="text-xs text-gray-400">Domain: {record.spfDomain || 'N/A'}</p>
                            </div>
                            <div className="text-right">
                              <div className={`text-sm font-medium ${
                                record.spfResult === 'pass' ? 'text-green-400' : 'text-red-400'
                              }`}>
                                {record.spfResult.toUpperCase()}
                              </div>
                              {record.spfResult === 'pass' && (
                                <div className={`text-xs ${
                                  record.spfAligned ? 'text-green-400' : 'text-red-400'
                                }`}>
                                  {record.spfAligned ? 'Aligned' : 'Not Aligned'}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Failure Reasons */}
                    {record.dmarcResult === 'fail' && record.reasons.length > 0 && (
                      <div className="mt-4 p-4 bg-red-900/20 border border-red-800/50 rounded-lg">
                        <div className="flex items-start gap-2">
                          <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
                          <div>
                            <p className="text-sm font-medium text-red-300">Failure Reasons:</p>
                            <ul className="text-sm text-red-200 mt-1 list-disc list-inside">
                              {record.reasons.map((reason, i) => (
                                <li key={i}>{reason}</li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;