import re
import typing
from markdown import Extension
from markdown.treeprocessors import Treeprocessor
import xml.etree.ElementTree as etree
import copy
from collections import OrderedDict


resolver = None


try:
    from pygments import highlight, format, lex
    from pygments.lexers import get_lexer_by_name, guess_lexer
    from pygments.lexers.python import PythonLexer
    from pygments.formatters import find_formatter_class
    from pygments import __version__ as pygments_ver

    from .vspythonlexer import VSPythonLexer
    from .highlight_resolver import HighlightResolver

    import docspec
    from pydoc_markdown.contrib.loaders.python import PythonLoader
    from pydoc_markdown.interfaces import Context
    from pygments.token import (
        _TokenType,
        Name,
    )

    def init_resolver():
        global resolver
        loader = PythonLoader()
        loader.init(Context(directory="."))

        modules = list(loader.load())
        resolver = HighlightResolver(modules)

    init_resolver()

    p_ver = tuple([int(n) for n in pygments_ver.split(".")[:2]])
    HtmlFormatter = find_formatter_class("html")
    pygments = True
except ImportError:
    pygments = False
    p_ver = (0, 0)

RE_PYG_CODE = re.compile(r'^<(div|table)(\s*class=".*?")?\s*>')
CODE_WRAP = "<pre{}><code{}{}{}>{}</code></pre>"
CODE_WRAP_ON_PRE = "<pre{}{}{}><code>{}</code></pre>"
CLASS_ATTR = ' class="{}"'
ID_ATTR = ' id="{}"'
DEFAULT_CONFIG = {
    "use_pygments": [
        True,
        "Use Pygments to highlight code blocks. "
        "Disable if using a JavaScript library. "
        "Default: True",
    ],
    "guess_lang": [False, "Automatic language detection - Default: False"],
    "css_class": ["highlight", "CSS class to apply to wrapper element."],
    "pygments_style": [
        "default",
        "Pygments HTML Formatter Style (color scheme) - Default: default",
    ],
    "noclasses": [False, "Use inline styles instead of CSS classes - Default false"],
    "linenums": [
        None,
        "Display line numbers in block code output (not inline) - Default: False",
    ],
    "linenums_style": ["table", 'Line number style -Default: "table"'],
    "linenums_special": [-1, "Globally make nth line special - Default: -1"],
    "linenums_class": [
        "linenums",
        "Control the linenums class name when not using Pygments - Default: 'linenums'",
    ],
    "extend_pygments_lang": [
        [],
        "Extend pygments language with special language entry - Default: []",
    ],
    "language_prefix": [
        "language-",
        'Controls the language prefix for non-Pygments code blocks. - Defaults: "language-"',
    ],
    "code_attr_on_pre": [
        False,
        "Attach attribute list values on pre element instead of code element - Default: False",
    ],
    "auto_title": [
        False,
        "Inject the lexer name as the title for block code - Defaults: False",
    ],
    "auto_title_map": [
        {},
        'User defined mapping of overrides for "auto_title" - Defaults: {}',
    ],
    "line_spans": [
        "",
        "If set to a nonempty string, e.g. foo, the formatter will wrap each output line "
        'in a span tag with an id of foo-<code_block_number>-<line_number>. . - Defaults: ""',
    ],
    "anchor_linenums": [
        False,
        "If set to True, will wrap line numbers in <a> tags. Used in combination with linenums and line_anchors."
        " - Defaults: False",
    ],
    "line_anchors": [
        "",
        "If set to a nonempty string, e.g. foo, the formatter will wrap each output line in an anchor tag with"
        ' an id (and name) of foo-<code_block_number>-<line_number>. - Defaults: ""',
    ],
    "_enabled": [
        True,
        "Used internally to communicate if extension has been explicitly enabled - Default: False",
    ],
}


if pygments:

    class InlineHtmlFormatter(HtmlFormatter):
        def wrap(self, source, outfile):
            return self._wrap_code(source)

        def _wrap_code(self, source):
            yield 0, ""
            for i, t in source:
                yield i, t.strip()
            yield 0, ""

    class BlockHtmlFormatter(HtmlFormatter):
        RE_SPAN_NUMS = re.compile(
            r'(<span[^>]*?)(class="[^"]*\blinenos?\b[^"]*)"([^>]*)>([^<]+)(</span>)'
        )
        RE_TABLE_NUMS = re.compile(r"(<pre[^>]*>)(?!<span></span>)")

        def __init__(self, **options):
            self.pymdownx_inline = options.get("linenos", False) == "pymdownx-inline"
            if self.pymdownx_inline:
                options["linenos"] = "inline"
            HtmlFormatter.__init__(self, **options)

        def _format_custom_line(self, m):
            if p_ver >= (2, 7):
                lnum = m.group(4) if not m.group(4).rstrip() else m.group(4)
            else:
                lnum = m.group(4)

            return (
                m.group(1)
                + m.group(2)
                + '"'
                + m.group(3)
                + ' data-linenos="'
                + lnum
                + ' ">'
                + m.group(5)
            )

        def _wrap_customlinenums(self, inner):
            for t, line in inner:
                if t:
                    line = self.RE_SPAN_NUMS.sub(self._format_custom_line, line)
                yield t, line

        def wrap(self, source, outfile):
            if self.linenos == 2 and self.pymdownx_inline:
                source = self._wrap_customlinenums(source)
            return HtmlFormatter.wrap(self, source, outfile)

        def _wrap_tablelinenos(self, inner):
            for t, line in HtmlFormatter._wrap_tablelinenos(self, inner):
                yield t, self.RE_TABLE_NUMS.sub(r"\1<span></span>", line)


class Highlight(object):
    def __init__(
        self,
        guess_lang=False,
        pygments_style="default",
        use_pygments=True,
        noclasses=False,
        extend_pygments_lang=None,
        linenums=None,
        linenums_special=-1,
        linenums_style="table",
        linenums_class="linenums",
        language_prefix="language-",
        code_attr_on_pre=False,
        auto_title=False,
        auto_title_map=None,
        line_spans="",
        anchor_linenums=False,
        line_anchors="",
    ):
        self.guess_lang = guess_lang
        self.pygments_style = pygments_style
        self.use_pygments = use_pygments
        self.noclasses = noclasses
        self.linenums = linenums
        self.linenums_style = linenums_style
        self.linenums_special = linenums_special
        self.linenums_class = linenums_class
        self.language_prefix = language_prefix
        self.code_attr_on_pre = code_attr_on_pre
        self.auto_title = auto_title
        self.line_spans = line_spans
        self.line_anchors = line_anchors
        self.anchor_linenums = anchor_linenums

        if self.anchor_linenums and not self.line_anchors:
            self.line_anchors = "__codelineno"

        if auto_title_map is None:
            auto_title_map = {}
        self.auto_title_map = auto_title_map

        if extend_pygments_lang is None:
            extend_pygments_lang = []
        self.extend_pygments_lang = {}
        for language in extend_pygments_lang:
            if isinstance(language, (dict, OrderedDict)):
                name = language.get("name")
                if name is not None and name not in self.extend_pygments_lang:
                    self.extend_pygments_lang[name] = [
                        language.get("lang"),
                        language.get("options", {}),
                    ]

    def get_extended_language(self, language):
        return self.extend_pygments_lang.get(language, (language, {}))

    def get_lexer(self, src, language):
        if language:
            language, lexer_options = self.get_extended_language(language)
        else:
            lexer_options = {}

        try:
            lexer = get_lexer_by_name(language, **lexer_options)
        except Exception:
            lexer = None

        if lexer is None:
            if self.guess_lang:
                try:
                    lexer = guess_lexer(src)
                except Exception:
                    pass

        if isinstance(lexer, PythonLexer):
            lexer = VSPythonLexer(**lexer_options)
        if lexer is None:
            lexer = get_lexer_by_name("text")
        return lexer

    def escape(self, txt):
        txt = txt.replace("&", "&amp;")
        txt = txt.replace("<", "&lt;")
        txt = txt.replace(">", "&gt;")
        return txt

    def highlight(
        self,
        src,
        language,
        css_class="highlight",
        hl_lines=None,
        linestart=-1,
        linestep=-1,
        linespecial=-1,
        inline=False,
        classes=None,
        id_value="",
        attrs=None,
        title=None,
        code_block_count=0,
    ):
        if attrs is None:
            attrs = {}
        class_names = classes[:] if classes else []
        linenums_enabled = (
            (self.linenums and linestart != 0)
            or (self.linenums is not False and linestart > 0)
        ) and not inline > 0

        if pygments and self.use_pygments:
            lexer = self.get_lexer(src, language)
            linenums = self.linenums_style if linenums_enabled else False

            if class_names:
                css_class = " {}".format("" if not css_class else css_class)
                css_class = " ".join(class_names) + css_class
                stripped = css_class.strip()

                if not isinstance(linenums, str) or linenums != "table":
                    css_class = stripped

            id_str = ID_ATTR.format(id_value) if id_value else ""

            if not attrs:
                attr_str = ""
            else:
                temp = []
                for k, v in attrs.items():
                    if k.startswith("data-"):
                        temp.append('{k}="{v}"'.format(k=k, v=v))
                attr_str = " " + " ".join(temp) if temp else ""

            if not linenums or linestep < 1:
                linestep = 1
            if not linenums or linestart < 1:
                linestart = 1
            if self.linenums_special >= 0 and linespecial < 0:
                linespecial = self.linenums_special
            if not linenums or linespecial < 0:
                linespecial = 0
            if hl_lines is None or inline:
                hl_lines = []

            if title is None and self.auto_title:
                name = " ".join(
                    [w.title() if w.islower() else w for w in lexer.name.split()]
                )
                title = self.auto_title_map.get(name, name)
            if title:
                title = title.strip()

            html_formatter = InlineHtmlFormatter if inline else BlockHtmlFormatter
            formatter = html_formatter(
                cssclass=css_class,
                linenos=linenums,
                linenostart=linestart,
                linenostep=linestep,
                linenospecial=linespecial,
                style=self.pygments_style,
                noclasses=self.noclasses,
                hl_lines=hl_lines,
                wrapcode=True,
                filename=title if not inline else "",
                linespans="{}-{:d}".format(self.line_spans, code_block_count)
                if self.line_spans and not inline
                else "",
                lineanchors=(
                    "{}-{:d}".format(self.line_anchors, code_block_count)
                    if self.line_anchors and not inline
                    else ""
                ),
                anchorlinenos=self.anchor_linenums if not inline else False,
            )

            if isinstance(lexer, VSPythonLexer):
                tokens: typing.List[typing.Tuple[_TokenType, str]] = []
                tokens_lex: typing.List[typing.Tuple[_TokenType, str]] = list(
                    lex(src, lexer)
                )

                nested_parent = []
                for token in tokens_lex:
                    tokenType = token[0]
                    var = token[1]
                    resolve = None

                    if tokenType == Name or tokenType == Name.Function:
                        nested_parent.append(var)
                        fullname = ".".join(nested_parent)
                        resolve = resolver.resolve_ref(fullname)

                    elif var != "." and var != ")" and len(nested_parent) > 0:
                        nested_parent.clear()

                    if resolve:
                        obj = resolve

                        if isinstance(obj, docspec.Function):
                            tokenType = Name.Function
                            for decoration in obj.decorations:
                                if (
                                    decoration.name == "property"
                                    or decoration.name.endswith(".setter")
                                ):
                                    tokenType = Name
                                    break

                        elif isinstance(obj, docspec.Indirection):
                            tokenType = Name.Class
                        elif isinstance(obj, docspec.Class):
                            tokenType = Name.Class
                        elif isinstance(obj, docspec.Module):
                            tokenType = Name.Namespace
                        else:
                            tokenType = Name

                    tokens.append((tokenType, var))

                code = format(tokens, formatter)

            else:
                code = highlight(src, lexer, formatter)

            if inline:
                class_str = css_class
                attr_str = ""
            else:
                m = RE_PYG_CODE.match(code)
                if m is not None:
                    end = m.end(0)
                    start = m.start(0)
                    classes = " " + m.group(2).lstrip() if m.group(2) else ""
                    code = "{}<{}{}{}{}>{}".format(
                        code[:start], m.group(1), id_str, classes, attr_str, code[end:]
                    )

        elif inline:
            code = self.escape(src)
            if css_class:
                class_names.insert(0, css_class)
            if language:
                class_names.insert(0, self.language_prefix + language)
            class_str = " ".join(class_names) if class_names else ""
            id_str = id_value
        else:
            if self.code_attr_on_pre and css_class:
                class_names.insert(0, css_class)
            if language:
                class_names.insert(0, self.language_prefix + language)
            class_str = CLASS_ATTR.format(" ".join(class_names)) if class_names else ""
            id_str = ID_ATTR.format(id_value) if id_value else ""
            attr_str = (
                " " + " ".join('{k}="{v}"'.format(k=k, v=v) for k, v in attrs.items())
                if attrs
                else ""
            )
            if not self.code_attr_on_pre:
                highlight_class = (CLASS_ATTR.format(css_class)) if css_class else ""
                code = CODE_WRAP.format(
                    highlight_class, id_str, class_str, attr_str, self.escape(src)
                )
            else:
                code = CODE_WRAP_ON_PRE.format(
                    id_str, class_str, attr_str, self.escape(src)
                )

        if inline:
            attributes = {}

            if class_str:
                attributes["class"] = class_str

            if id_str:
                attributes["id"] = id_str
            for k, v in attrs:
                attributes[k] = v

            el = etree.Element("code", attributes)
            el.text = code
            return el
        else:
            return code.strip()


class HighlightTreeprocessor(Treeprocessor):
    def __init__(self, md, ext):
        self.ext = ext
        super(HighlightTreeprocessor, self).__init__(md)

    def code_unescape(self, text):
        text = text.replace("&lt;", "<")
        text = text.replace("&gt;", ">")
        text = text.replace("&amp;", "&")
        return text

    def run(self, root):
        blocks = root.iter("pre")
        for block in blocks:
            if len(block) == 1 and block[0].tag == "code":
                self.ext.pygments_code_block += 1
                code = Highlight(
                    guess_lang=self.config["guess_lang"],
                    pygments_style=self.config["pygments_style"],
                    use_pygments=self.config["use_pygments"],
                    noclasses=self.config["noclasses"],
                    linenums=self.config["linenums"],
                    linenums_style=self.config["linenums_style"],
                    linenums_special=self.config["linenums_special"],
                    linenums_class=self.config["linenums_class"],
                    extend_pygments_lang=self.config["extend_pygments_lang"],
                    language_prefix=self.config["language_prefix"],
                    code_attr_on_pre=self.config["code_attr_on_pre"],
                    auto_title=self.config["auto_title"],
                    auto_title_map=self.config["auto_title_map"],
                )
                placeholder = self.md.htmlStash.store(
                    code.highlight(
                        self.code_unescape(block[0].text),
                        "",
                        self.config["css_class"],
                        code_block_count=self.ext.pygments_code_block,
                    )
                )

                block.clear()
                block.tag = "p"
                block.text = placeholder


class HighlightExtension(Extension):
    def __init__(self, *args, **kwargs):
        self.config = copy.deepcopy(DEFAULT_CONFIG)
        super(HighlightExtension, self).__init__(*args, **kwargs)

    def get_pymdownx_highlight_settings(self):
        target = None

        if self.enabled:
            target = self.getConfigs()

        if target is None:
            target = {}
            config_clone = copy.deepcopy(DEFAULT_CONFIG)
            for k, v in config_clone.items():
                target[k] = config_clone[k][0]

        return target

    def get_pymdownx_highlighter(self):
        return Highlight

    def extendMarkdown(self, md):
        config = self.getConfigs()
        self.pygments_code_block = -1
        self.md = md
        self.enabled = config.get("_enabled", False)

        if self.enabled:
            ht = HighlightTreeprocessor(self.md, self)
            ht.config = self.getConfigs()
            self.md.treeprocessors.register(ht, "indent-highlight", 30)

        index = 0
        register = None
        for ext in self.md.registeredExtensions:
            if isinstance(ext, HighlightExtension):
                register = not ext.enabled and self.enabled
                break

        if register is None:
            register = True
            index = -1

        if register:
            if index == -1:
                self.md.registerExtension(self)
            else:
                self.md.registeredExtensions[index] = self

    def reset(self):
        self.pygments_code_block = -1


def makeExtension(*args, **kwargs):
    return HighlightExtension(*args, **kwargs)
