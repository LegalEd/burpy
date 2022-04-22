from burp import IBurpExtender
from burp import IContextMenuFactory
from javax.swing import JMenuItem
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.awt.event import ActionListener


class BurpExtender(IBurpExtender, IContextMenuFactory, ActionListener):
    """a Burp extension to convert Burp requests into scrapy yield statments"""

    def __init__(self):
        self.menuItem = JMenuItem("burpy")
        self.menuItem.addActionListener(self)

    def registerExtenderCallbacks(self, callbacks):
        self._helpers = callbacks.getHelpers()
        self._callbacks = callbacks
        callbacks.setExtensionName("burpy")
        callbacks.registerContextMenuFactory(self)

        print("running burpy....")
        print(
            """
 _____ _____ _____ _____ __ __
| __  |  |  | __  |  _  |  |  |
| __ -|  |  |    -|   __|_   _|
|_____|_____|__|__|__|    |_|

"""
        )
        return

    def createMenuItems(self, invocation):
        self.invocation = invocation
        self.messages = invocation.getSelectedMessages()
        return [self.menuItem]

    def _build(self):
        if not self.messages:
            print("error - no request selected")
            return

        iRequestInfo = self._helpers.analyzeRequest(
            self.invocation.getSelectedMessages()[0]
        )

        if iRequestInfo is None:
            return

        headers = iRequestInfo.getHeaders()
        headers = dict(item.split(": ") for item in iRequestInfo.getHeaders()[1:])
        headers = dict(
            (k, v) for k, v in headers.iteritems() if "Cookie" not in k
        )
        cookies = iRequestInfo.getParameters()
        cookies = [
            c.split(": ")[1]
            for c in iRequestInfo.getHeaders() if "Cookie" in c
        ]
        cookies = ''.join(cookies)

        print("scrapy yield statement is...")

        if iRequestInfo.method == "POST":
            thing = self.messages[0]
            a = self._helpers.analyzeRequest(thing.getRequest())
            b = self._helpers.bytesToString(thing.getRequest()[a.getBodyOffset():])
            body = "".join(chr(ord(c)) for c in b)
            # jython doesn't include fstrings. Have to use format!
            output = """yield scrapy.Request(
                url="{}",
                method="{}",
                headers={},
                cookies={},
                body={})""".format(iRequestInfo.url, iRequestInfo.method, headers, cookies, body)

        else:
            output = """yield scrapy.Request(
                url='{}',
                method='{}',
                headers={},
                cookies={})""".format(iRequestInfo.url, iRequestInfo.method, headers, cookies)

        print(output)

        # Nasty - invocation of some java code to get the string on the clipboard
        s = StringSelection(output)
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
            s, s
        )  # put string on clipboard

    def actionPerformed(self, actionEvent):  # actionEvent is required param but not called
        self._build()
