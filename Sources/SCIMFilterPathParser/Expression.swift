import Foundation

public protocol Expression: CustomScimFilterStringConvertible, Hashable {
	
}

public enum PathExpression: Expression, Hashable {
	case attributePath(AttributePath)
	case valuePathExpression(ValuePathExpression, String?)
	case attributeExpression(AttributeExpression)
	
	public var scimFilterString: String {
		switch self {
		case let .attributePath(attrPath):
			return attrPath.scimFilterString
		case let .valuePathExpression(valPath, subAttr):
			if let subAttr = subAttr {
				return valPath.scimFilterString + "." + subAttr
			} else {
				return valPath.scimFilterString
			}
		case let .attributeExpression(attrExpr):
			return attrExpr.scimFilterString
		}
	}
}

public struct FilterExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	public var anyExpr: FilterAnyExpression
	
	public var scimFilterString: String {
		return anyExpr.scimFilterString
	}
}

public struct FilterAnyExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	public var anyExprs: [FilterAllExpression]
	
	public var scimFilterString: String {
		return anyExprs.map({ $0.scimFilterString }).joined(separator: " or ")
	}
}

public struct FilterAllExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	public var allExprs: [FilterValueExpression]
	
	public var scimFilterString: String {
		return allExprs.map({ $0.scimFilterString }).joined(separator: " and ")
	}
}

public indirect enum FilterValueExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	case attributeExpression(AttributeExpression)
	case valuePathExpression(ValuePathExpression)
	case groupedFilter(FilterExpression)
	case negatedGroupedFilter(FilterExpression)
	
	public var scimFilterString: String {
		switch self {
		case let .attributeExpression(attrExpr):
			return attrExpr.scimFilterString
		case let .valuePathExpression(valuePath):
			return valuePath.scimFilterString
		case let .groupedFilter(filter):
			return "(\(filter.scimFilterString))"
		case let .negatedGroupedFilter(filter):
			return "not (\(filter.scimFilterString))"
		}
	}
}

public struct ValuePathExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	public let attributePath: AttributePath
	public let valueFilterExpression: ValueFilterExpression
	
	public var scimFilterString: String {
		return "\(attributePath.scimFilterString)[\(valueFilterExpression.scimFilterString)]"
	}
}

public struct ValueFilterExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	public var anyExpr: ValueFilterAnyExpression
	
	public var scimFilterString: String {
		return anyExpr.scimFilterString
	}
}

public struct ValueFilterAnyExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	public var anyExprs: [ValueFilterAllExpression]
	
	public var scimFilterString: String {
		return anyExprs.map({ $0.scimFilterString }).joined(separator: " or ")
	}
}

public struct ValueFilterAllExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	public var allExprs: [ValueFilterValueExpression]
	
	public var scimFilterString: String {
		return allExprs.map({ $0.scimFilterString }).joined(separator: " and ")
	}
}

public indirect enum ValueFilterValueExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	case attributeExpression(AttributeExpression)
	case groupedValueFilter(ValueFilterExpression)
	case negatedGroupedValueFilter(ValueFilterExpression)
	
	public var scimFilterString: String {
		switch self {
		case let .attributeExpression(attrExpr):
			return attrExpr.scimFilterString
		case let .groupedValueFilter(valFilter):
			return "(\(valFilter.scimFilterString))"
		case let .negatedGroupedValueFilter(valFilter):
			return "not (\(valFilter.scimFilterString))"
		}
	}
}

public enum AttributeExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	case present(AttributePresentExpression)
	case comparison(AttributeComparisonExpression)
	
	public var scimFilterString: String {
		switch self {
		case let .present(attrPresentExpr):
			return attrPresentExpr.scimFilterString
		case let .comparison(attrCompExpr):
			return attrCompExpr.scimFilterString
		}
	}
}

public struct AttributePresentExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	public let attributePath: AttributePath
	
	public var scimFilterString: String {
		return "\(attributePath.scimFilterString) pr"
	}
}

public struct AttributeComparisonExpression: Expression, CustomScimFilterStringConvertible, Hashable {
	public let attributePath: AttributePath
	public let comparativeOperator: ComparativeOperator
	public let comparativeValue: ComparativeValue
	
	public var scimFilterString: String {
		return "\(attributePath.scimFilterString) \(comparativeOperator.scimFilterString) \(comparativeValue.scimFilterString)"
	}
}

public enum ComparativeValue: CustomScimFilterStringConvertible, Hashable {
	case `false`
	case `null`
	case `true`
	case number(String)
	case string(String, String)
	
	public var scimFilterString: String {
		switch self {
		case .false:
			return "false"
		case .null:
			return "null"
		case .true:
			return "true"
		case let .number(numberString):
			return numberString
		case let .string(_, literalRepresentation):
			return literalRepresentation
		}
	}
}

public enum ComparativeOperator: String, CustomScimFilterStringConvertible, Hashable {
	case eq = "eq"
	case ne = "ne"
	case co = "co"
	case sw = "sw"
	case ew = "ew"
	case gt = "gt"
	case ge = "ge"
	case lt = "lt"
	case le = "le"
	
	public var scimFilterString: String {
		return self.rawValue
	}
}

public struct AttributePath: CustomScimFilterStringConvertible, Hashable {
	public var schemaUrn: String? = nil
	public let attributeName: String
	public var subAttributeName: String? = nil
	
	public var scimFilterString: String {
		var result = attributeName
		if let schemaUrn = schemaUrn {
			result = schemaUrn + ":" + result
		}
		if let subAttr = subAttributeName {
			result = result + "." + subAttr
		}
		return result
	}
}

public enum LogicalOperator: String, CustomScimFilterStringConvertible, Hashable {
	case and = "and"
	case or = "or"
	
	public var scimFilterString: String {
		return self.rawValue
	}
}
