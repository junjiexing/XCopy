import idaapi
import ida_kernwin
from PyQt5.QtWidgets import QApplication


class XMenuContext(ida_kernwin.action_handler_t):
	@classmethod
	def get_name(self):
		return self.__name__

	@classmethod
	def register(self, label):
		return idaapi.register_action(idaapi.action_desc_t(
				self.get_name(),
				label,
				self()
			))

	@classmethod
	def unregister(self):
		idaapi.unregister_action(self.get_name())

	@classmethod
	def update(self, ctx):
		return ida_kernwin.AST_ENABLE_ALWAYS

	@classmethod
	def set_clipboard(self, txt):
		cb = QApplication.clipboard()
		cb.setText(txt, mode=cb.Clipboard)
		print("copied", txt)


class CopyVA(XMenuContext):
	def activate(self, ctx):
		cur = ida_kernwin.get_screen_ea()
		self.set_clipboard(hex(cur))


class CopyRVA(XMenuContext):
	def activate(self, ctx):
		cur = ida_kernwin.get_screen_ea()
		base = idaapi.get_imagebase()
		self.set_clipboard(hex(cur - base))


class CopyRVAX96(XMenuContext):
	def activate(self, ctx):
		cur = ida_kernwin.get_screen_ea()
		base = idaapi.get_imagebase()
		self.set_clipboard(":$" + hex(cur - base))


class UIHooks(idaapi.UI_Hooks):
	def finish_populating_widget_popup(self, form, popup):
		wt = idaapi.get_widget_type(form)
		if wt == idaapi.BWN_DISASM or wt == idaapi.BWN_PSEUDOCODE:
			try:
				idaapi.attach_action_to_popup(form, popup, CopyVA.get_name(), 'XCopy/')
				idaapi.attach_action_to_popup(form, popup, CopyRVA.get_name(), 'XCopy/')
				idaapi.attach_action_to_popup(form, popup, CopyRVAX96.get_name(), 'XCopy/')
			except:
				pass

class XCopy(idaapi.plugin_t):
	flags = idaapi.PLUGIN_KEEP
	wanted_name = "XCopy"
	comment = "A plug-in to enhance IDA's copy function"

	def init(self):
		CopyVA.register("Copy VA")
		CopyRVA.register("Copy RVA")
		CopyRVAX96.register("Copy RVA(x96dbg)")

		self.hooks = UIHooks()
		self.hooks.hook()

		# idaapi.attach_action_to_menu("Edit", CopyVA.get_name(), idaapi.SETMENU_APP)
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		print("-"*86)
		print("XCopy by Xing")
		print("https://blog.xing.re")
		# print(self.comment)
		print("-"*86)


	def term(self):
		if self.hooks is not None:
			self.hooks.unhook()
			self.hooks = None
		return idaapi.PLUGIN_OK

def PLUGIN_ENTRY():
	return XCopy()

