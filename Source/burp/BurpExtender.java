/*
	BurpExtender.java
	
	v0.3 (12/22/2015)
	
	SuperSerial - Passive
	
	Extension including passive scan check for Java serialized objects in server response. Checks are based on response 
	content-type and data. Scanner issue is created if content-type is application/x-java-serialized-object OR 
	content-type is application/octet-stream AND response body starts with 0xACED0005. This extension does not do any 
	form of vulnerability exploitation, only potentional vulnerability detection.
*/

package burp;

import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.net.URL;

public class BurpExtender implements IBurpExtender,IScannerCheck {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	
	private static final String CONTENT_TYPE = "application/x-java-serialized-object";
	private static final byte FILE_HEADER_0 = (byte) 172; //0xAC
	private static final byte FILE_HEADER_1 = (byte) 237; //0xED
	private static final byte FILE_HEADER_2 = 0x00; //0x00
	private static final byte FILE_HEADER_3 = 0x05; //0x05
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks mCallbacks) {
		callbacks = mCallbacks;
		helpers = callbacks.getHelpers();
		
		callbacks.setExtensionName("SuperSerial - Passive");
		
		callbacks.registerScannerCheck(this);
	}
	
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		List<IScanIssue> issues = null; //issues to report (if any)
		
		//check 1: search for plain-text Java serialized objects in request and response (JBoss)
		byte[] req = baseRequestResponse.getRequest();
		IRequestInfo reqInfo = helpers.analyzeRequest(req);
		byte[] resp = baseRequestResponse.getResponse();
		IResponseInfo respInfo = helpers.analyzeResponse(resp);
		
		int[][] reqHighlights = processJBossRequest(reqInfo,req);
		int[][] respHighlights = processJBossResponse(respInfo,resp);
		ArrayList<int[]> reqMarkers = null;
		ArrayList<int[]> respMarkers = null;
		
		//parse results
		int resId = 0;
		if(reqHighlights!=null) { //vuln found in request
			reqMarkers = new ArrayList<int[]>(2);
			if(reqHighlights[0]!=null) { //request content-type header found
				resId = resId | 1;
				reqMarkers.add(reqHighlights[0]);
			}
			if(reqHighlights[1]!=null) { //request serialized data found
				resId = resId | 2;
				reqMarkers.add(reqHighlights[1]);
			}
		}
		if(respHighlights!=null) { //vuln found in response
			respMarkers = new ArrayList<int[]>(2);
			if(respHighlights[0]!=null) {
				resId = resId | 4;
				respMarkers.add(respHighlights[0]);
			}
			if(respHighlights[1]!=null) {
				resId = resId | 8;
				respMarkers.add(respHighlights[1]);
			}
		}
		
		if(resId>0) { //potentional JBoss vuln found, create highlight Request/Response and scanner issue (with approriate detail ID)
			issues = new ArrayList<IScanIssue>(1);
			IHttpRequestResponseWithMarkers issueRR = callbacks.applyMarkers(baseRequestResponse,reqMarkers,respMarkers);
			SerializationRCEScanIssue issue = new SerializationRCEScanIssue(issueRR,issueRR.getHttpService(),helpers.analyzeRequest(issueRR).getUrl(),resId,0);
			issues.add(issue);
			return issues;
		} else {
			
			//check 2: search for base64-encoded java serialized object(s) in response only (WebSphere)
			respHighlights = null;
			
			if(respInfo.getStatedMimeType().equalsIgnoreCase("XML") || respInfo.getInferredMimeType().equalsIgnoreCase("XML")) { //if response contains XML, convert to request for easy parsing
				int respDataStart = respInfo.getBodyOffset();
				byte[] respData = new byte[resp.length-respDataStart];
				int i=respDataStart;
				int j=0;
				while(i<resp.length) {
					respData[j] = resp[i];
					i++;
					j++;
				}
				
				byte[] respReq = helpers.buildHttpMessage(reqInfo.getHeaders(),respData);
				IRequestInfo respReqInfo = helpers.analyzeRequest(respReq);
				List<IParameter> params = respReqInfo.getParameters();
				Iterator<IParameter> paramsItr = params.iterator();
				ArrayList<byte[]> results = new ArrayList<byte[]>();
				while(paramsItr.hasNext()) { //Search for XML values starting with "rO0AB"
					IParameter param = paramsItr.next();
					String paramVal = param.getValue();
					if((paramVal.length()>=4) && (paramVal.substring(0,5).equals("rO0AB"))) {
						byte[] decoded = helpers.base64Decode(paramVal);
						if(decoded.length>=4) {
							if(decoded[0] == FILE_HEADER_0) {
								if(decoded[1] == FILE_HEADER_1) {
									if(decoded[2] == FILE_HEADER_2) {
										if(decoded[3] == FILE_HEADER_3) {
											results.add(paramVal.getBytes());
										}
									}
								}
							}
						}
					}
				}
				
				int resStart;
				if(results.size()>0) { //potential WebSphere vuln found, create highlight indexes and create issue (with "response data only" detail ID and base64 confirmed encId)
					respMarkers = new ArrayList<int[]>();
					Iterator<byte[]> resultsItr = results.iterator();
					while(resultsItr.hasNext()) {
						byte[] result = resultsItr.next();
						resStart = helpers.indexOf(resp,result,true,respDataStart,resp.length);
						int[] marker = {resStart,resStart+result.length};
						respMarkers.add(marker);
					}
					
					issues = new ArrayList<IScanIssue>(1);
					IHttpRequestResponseWithMarkers issueRR = callbacks.applyMarkers(baseRequestResponse,null,respMarkers);
					SerializationRCEScanIssue issue = new SerializationRCEScanIssue(issueRR,issueRR.getHttpService(),helpers.analyzeRequest(issueRR).getUrl(),8,2);
					issues.add(issue);
					return issues;
				}
			} else { //not XML: search indiscriminately for "rO0AB" string in response body
				int searchIndex = respInfo.getBodyOffset();
				ArrayList<int[]> results = new ArrayList<int[]>();
				
				int resStart = 0;
				while(resStart!=-1) {
					resStart = helpers.indexOf(resp,"rO0AB".getBytes(),true,searchIndex,resp.length);
					if(resStart!=-1 && (!isBase64Char(resp[resStart-1]))) { //if value was found and appears to be start of base64-encoded value: add result
						results.add(new int[] {resStart,resStart+5});
						searchIndex=resStart+5;
					}
				}
				
				if(results.size()>0) { //potential WebSphere vuln found, create highlight indexes and create issue (with "response data only" detail ID and base64 unconfirmed encId)
					respMarkers = results;
					issues = new ArrayList<IScanIssue>(1);
					IHttpRequestResponseWithMarkers issueRR = callbacks.applyMarkers(baseRequestResponse,null,respMarkers);
					SerializationRCEScanIssue issue = new SerializationRCEScanIssue(issueRR,issueRR.getHttpService(),helpers.analyzeRequest(issueRR).getUrl(),8,1);
					issues.add(issue);
				}
			}
		}
		
		return issues;
	}
	
	//no active scan checks for this extension, therefore do nothing here
	@Override
	public java.util.List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,IScannerInsertionPoint insertionPoint) {
		return null;
	}
	
	/*same HTTP method:
	*	duplicate Issue Detail: duplicate vulnerability (report existing only)
	*	different Issue Detail:
	*		existing issue did not include data, new issue does: new vulnerability (report new only)
	*		existing issue included data but not in response, new issue does: new vulnerability (report new only)
	*different HTTP methods: new vulnerability (report both) */
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue,IScanIssue newIssue) {
		String eMethod = null;
		String nMethod = null;
		
		//get HTTP method from issues
		IHttpRequestResponse[] rr = existingIssue.getHttpMessages();
		byte[] req = rr[0].getRequest();
		IRequestInfo reqInfo = helpers.analyzeRequest(req);
		eMethod = reqInfo.getMethod(); //retrieve existingIssue HTTP method
		rr = newIssue.getHttpMessages();
		req = rr[0].getRequest();
		reqInfo = helpers.analyzeRequest(req);
		nMethod = reqInfo.getMethod(); //retrieve newIssue HTTP method
		
		//compare existing and new issues
		int retVal = 0;
		if(eMethod.equals(nMethod)) { //same HTTP method
			String existingIssueDetail = existingIssue.getIssueDetail();
			String newIssueDetail = newIssue.getIssueDetail();
			if(existingIssueDetail.equals(newIssueDetail)) {
				retVal = -1; //duplicate issue
			} else {
				if(!existingIssueDetail.contains("0xACED0005") && newIssueDetail.contains("0xACED0005")) { //existing issue does not contain serialized data, new issue does: replace
					retVal = 1;
				} else if(existingIssueDetail.contains("0xACED0005") && newIssueDetail.contains("0xACED0005")) {
					if(!existingIssueDetail.contains("server response body began with") && newIssueDetail.contains("server response body began with")) { //existing issue does not contain serialized data in response, new issue does: replace
						retVal = 1;
					}
				}
			}
		}
		
		return retVal;
	}
	
	
	//helper methods
	
	//check for vuln in request
	private int[][] processJBossRequest(IRequestInfo reqInfo,byte[] req) {
		int dataStart = reqInfo.getBodyOffset();
		List<String> headers = reqInfo.getHeaders();
		return processJBossMessage(headers,req,dataStart);
	}
	
	//check for vuln in response
	private int[][] processJBossResponse(IResponseInfo respInfo,byte[] resp) {
		int dataStart = respInfo.getBodyOffset();
		List<String> headers = respInfo.getHeaders();
		return processJBossMessage(headers,resp,dataStart);
	}
	
	//check for vuln
	//return values:
	//null: no vulns found
	//int[2]: vuln found
	//	if int[0] is defined: content-type header found
	//	if int[1] is defined: data found
	private int[][] processJBossMessage(List<String> headers,byte[] message,int dataStart) {
		int[][] highlights = null;
		boolean vuln = false; //if a potential vulnerability is found
		boolean contentHighlight = false; //if correct content-type header is found and should be highlighted
		int contentStart = -1; //start of content-type
		int contentEnd = -1; //end of content-type
		boolean dataHighlight = false; //if serialized object header was found and should be highlighted
		
		//first check: check content-type
		Iterator<String> headerItr = headers.iterator();
		while(headerItr.hasNext()) {
			String header = headerItr.next();
			String[] headerSplit = header.split(":",2);
			if((headerSplit.length>1) && (headerSplit[0].equalsIgnoreCase("Content-Type"))) { //content-type header found
				String val = headerSplit[1].trim();
				if(val.contains(CONTENT_TYPE)) { //content-type is expected type, set flags for vuln found and highlight content
					vuln = true;
					contentHighlight = true;
					contentStart = helpers.indexOf(message,header.getBytes(),true,0,message.length);
					contentEnd = contentStart+header.length();
					break;
				}
			}
		}
		
		//second check: check actual data
		//if(data.length>=4) { //data must be at least 4 bytes long; check for serialized object by file header
		if((message.length-dataStart)>=4) { //data must be at least 4 bytes long; check for serialized object by file header
			if(message[dataStart] == FILE_HEADER_0) { //first byte: 0xAC
				if(message[dataStart+1] == FILE_HEADER_1) { //second byte: 0xED
					if(message[dataStart+2] == FILE_HEADER_2) { //third byte: 0x00
						if(message[dataStart+3] == FILE_HEADER_3) { //fourth byte: 0x05
							vuln = true;
							dataHighlight = true;
						} else {
							if(!contentHighlight) vuln = false; //unless content-type is expected type, not a vuln
						}
					} else {
						if(!contentHighlight) vuln = false; //unless content-type is expected type, not a vuln
					}
				} else {
					if(!contentHighlight) vuln = false; //unless content-type is expected type, not a vuln
				}
			} else {
				if(!contentHighlight) vuln = false; //unless content-type is expected type, not a vuln
			}
		}
		
		//if one or both vuln criteria were met, create arrays of necessary highlights
		if(vuln) {
			highlights = new int[2][2];
			highlights[0] = null;
			highlights[1] = null;
			
			if(contentHighlight) highlights[0] = new int[] {contentStart,contentEnd};
			if(dataHighlight) highlights[1] = new int[] {dataStart,message.length};
		}
		
		return highlights;
	}
	
	//test if inputted char belongs to the base64 character-set
	private boolean isBase64Char(byte b) {
		byte[] base64Chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+".getBytes();
		for(int i=0;i<base64Chars.length;i++) {
			if(b==base64Chars[i]) return true;
		}
		return false;
	}
}