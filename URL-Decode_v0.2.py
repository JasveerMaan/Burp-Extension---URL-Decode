#Author: Jasveer Singh <jasveermaan06@gmail.com>

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
	
	#
	# implement IBurpExtender
	#
	
	def registerExtenderCallbacks(self, callbacks):
		# keep a reference to our callbacks object
		self._callbacks = callbacks
		
		# obtain an extension helpers object
		self._helpers = callbacks.getHelpers()
		
		# set our extension name
		callbacks.setExtensionName("URL Decoder v0.2")
		
		# register ourselves as a message editor tab factory
		callbacks.registerMessageEditorTabFactory(self)
		
	# 
	# implement IMessageEditorTabFactory
	#
	
	def createNewInstance(self, controller, editable):
		# create a new instance of our custom editor tab
		return URLDecodeTab(self, controller, editable)

		
# 
# class implementing IMessageEditorTab
#

class URLDecodeTab(IMessageEditorTab):
	def __init__(self, extender, controller, editable):
		self._extender = extender
		self._editable = editable
		
		# create an instance of Burp's text editor, to display our deserialized data
		self._txtInput = extender._callbacks.createTextEditor()
		self._txtInput.setEditable(editable)

		
	#
	# implement IMessageEditorTab
	#

	def getTabCaption(self):
		return "URL Decode Output"
		
	def getUiComponent(self):
		return self._txtInput.getComponent()
		
	def isEnabled(self, content, isRequest):
		# enable this tab for requests containing a message parameter
		return isRequest and not self._extender._helpers.getRequestParameter(content, "message") is None
		
	def setMessage(self, content, isRequest):
		if content is None:
			# clear our display
			self._txtInput.setText(None)
			self._txtInput.setEditable(editable)
		
		else:
			# retrieve the message parameter
			parameter = self._extender._helpers.getRequestParameter(content, "message")
			
			# deserialize the parameter value
			print "[!] URL decoding"
			self._txtInput.setText(self._extender._helpers.urlDecode(parameter.getValue()))
			self._txtInput.setEditable(self._editable)
		
		# remember the displayed content
		self._currentMessage = content
		return
		
	def getMessage(self):
		#Will print and to let us know if the text is modified or not
		print("Is the text modified? " + str(self._txtInput.isTextModified()))
		#This will text place if text is modified
		if self._txtInput.isTextModified():
			try:
				http_request = self._extender._helpers.analyzeRequest(self._currentMessage)
				http_headers = http_request.getHeaders()
				original_http_body = self._currentMessage[http_request.getBodyOffset():].tostring()
				print "original http body" + str(original_http_body)
				original_message_value = original_http_body.split("message=")[1].split("&")[0]
				#Reading the modified text
				text = self._txtInput.getText()
				print "[!]This is the decoded text: " + text
				print "[!]Constructing the modified body"
				modified_message_value = self._extender._helpers.urlEncode(text)
				modified_message_value = self._extender._helpers.bytesToString(modified_message_value)
				print "[!]This is modified HTTP Body: "
				modified_http_body = original_http_body.replace(original_message_value, modified_message_value)
				print(modified_http_body)
				self._currentMessage  = self._extender._helpers.buildHttpMessage(http_headers,self._extender._helpers.stringToBytes(modified_http_body))
				return self._currentMessage
			except Exception, e:
				print "[!]getMessage Exception: " + str(e)
		else:
			return self._currentMessage

	
	def isModified(self):
		return self._txtInput.isTextModified()
	
	def getSelectedData(self):
		return self._txtInput.getSelectedText()