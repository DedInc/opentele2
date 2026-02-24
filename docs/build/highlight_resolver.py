import typing as t

import docspec


class HighlightResolver:
    def __init__(self, modules: t.List[docspec.Module]) -> None:
        self.modules = modules
        self.dummyClass = docspec.Class(
            "dummy_class", None, None, None, None, None, None, None, None
        )

    def GetObjectID(self, obj: docspec.ApiObject) -> str:
        parts = []
        while obj:
            parts.append(obj.name)
            obj = obj.parent
        return ".".join(reversed(parts))

    def GetObjectModule(self, obj: docspec.ApiObject) -> docspec.Module:
        while not isinstance(obj, docspec.Module):
            obj = obj.parent
        return obj

    def FindModuleByName(self, moduleName: str) -> t.Optional[docspec.Module]:
        for module in self.modules:
            if module.name == moduleName:
                return module
        return None

    def FindRefInModule(
        self,
        module: docspec.Module,
        refNames: t.List[str],
        typeFilter: t.List[t.Type[docspec.ApiObject]] = [],
    ) -> t.Optional[docspec.ApiObject]:
        if isinstance(refNames, str):
            refNames = [refNames]

        def find(module: docspec.Module, name: str) -> t.Optional[docspec.ApiObject]:
            for member in module.members:
                if member.name == partName and (
                    (len(typeFilter) == 0) or (type(member) in typeFilter)
                ):
                    return member

            return None

        checkObj = module
        for partName in refNames:
            if not isinstance(checkObj, docspec.HasMembers):
                return None

            checkObj = find(checkObj, partName)
            if checkObj is None:
                break

        return checkObj

    def FindAllReference(
        self,
        obj: docspec.ApiObject,
        refNames: t.List[str],
        typeFilter: t.List[t.Type[docspec.ApiObject]] = [],
        excpt: docspec.ApiObject = None,
        inherited: bool = False,
    ) -> t.Tuple[t.List[docspec.ApiObject], t.List[docspec.ApiObject]]:
        easyFind = self.FindRefInModule(obj, refNames[-1], typeFilter)
        hardFind = self.FindRefInModule(obj, refNames, typeFilter)
        easyResults = [easyFind] if easyFind is not None else []
        hardResults = [hardFind] if hardFind is not None else []

        if isinstance(obj, docspec.HasMembers):
            for member in obj.members:
                if member != excpt:
                    search = self.FindAllReference(
                        member, refNames, typeFilter, None, True
                    )
                    easyResults.extend(search[0])
                    hardResults.extend(search[1])

        if not inherited:
            parent = obj.parent

            if parent is None:
                for module in self.modules:
                    if module != excpt:
                        search = self.FindAllReference(
                            module, refNames, typeFilter, None, True
                        )
                        easyResults.extend(search[0])
                        hardResults.extend(search[1])
            else:
                search = self.FindAllReference(parent, refNames, typeFilter, obj, False)
                easyResults.extend(search[0])
                hardResults.extend(search[1])

        return (easyResults, hardResults)

    def resolve_ref(
        self,
        reference: str,
        typeFilter: t.List[t.Type[docspec.ApiObject]] = [],
    ) -> t.Optional[docspec.ApiObject]:
        obj = self.modules[0]
        while True:
            parent = obj.parent
            if parent is None:
                break
            obj = parent

        refNames = reference.split(".")
        easyResult, hardResult = self.FindAllReference(obj, refNames, typeFilter)

        for result in hardResult:
            return result

        for result in easyResult:
            return result

        return None
