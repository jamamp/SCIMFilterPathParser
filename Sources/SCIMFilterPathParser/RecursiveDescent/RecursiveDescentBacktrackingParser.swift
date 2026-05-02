import Foundation

// TODO: Detect and error upon ATTRNAME.subAttr[valFilter]

// Uses SCIM_RFC_7644_LeftRecursionEliminatedV2.abnf

/// 
public class RecursiveDescentBacktrackingParser: RecursiveDescentPredictiveBase, Parser {
	
	private(set) var attemptParseTokenStack: [(String.Index, Token)] = []
	
	public override init(filter: String) throws {
		try super.init(filter: filter)
	}
	
	/// Parses a filter from the grammar.
	/// This expects the entire input string to be parsed, and will fail if no
	/// EOF is encountered at the end.
	///
	/// Symbol: `FILTER`
	/// Type: Backtracking
	public func parseFilter() throws -> FilterExpression {
		let filter = try parseFilterInternal()
		try expect(token: .eof)
		return filter
	}
	
	/// Parses a path from the grammar.
	/// This expects the entire input string to be parsed, and will fail if no
	/// EOF is encountered at the end.
	///
	/// Symbol: `PATH`
	/// Type: Backtracking
	public func parsePath() throws -> PathExpression {
		if let valuePath = attemptParse({ try parseValuePath() }) {
			// Try valuePath first, since it's the longest and most complex
			var subAttr: String? = nil
			if try attempt(token: .dot) {
				subAttr = try parseAttributeIdentifier()
			}
			try expect(token: .eof)
			return .valuePathExpression(valuePath, subAttr)
		} else if let attrExp = attemptParse({ try parseAttributeExpression() }) {
			// Try attrExp next, before attrPath, as it is a superset of attrPath
			try expect(token: .eof)
			return .attributeExpression(attrExp)
		} else if let attrPath = attemptParse({ try parseAttributePath() }) {
			try expect(token: .eof)
			return .attributePath(attrPath)
		} else {
			throw ParserError(message: "Could not parse the path (no viable option was found)")
		}
	}
}

// Internal helper methods
extension RecursiveDescentBacktrackingParser {
	func attemptParse<T>(_ closure: () throws -> T) -> T? {
		lexer.pushSnapshot()
		attemptParseTokenStack.append((currentTokenIndex, currentToken))
		
		do {
			let parseResult = try closure()
			
			lexer.discardSnapshot()
			_ = attemptParseTokenStack.popLast()
			
			return parseResult
		} catch {
			lexer.popSnapshot()
			if let currentTokenSnapshot = attemptParseTokenStack.popLast() {
				currentTokenIndex = currentTokenSnapshot.0
				currentToken = currentTokenSnapshot.1
			}
			
			return nil
		}
	}
}

// Internal node parsers
extension RecursiveDescentBacktrackingParser {
	
	/// Parses a filter from the grammar.
	/// This does not expect an EOF at the end, so that it can be used for
	/// recursive parsing from `parseFilterValue`.
	///
	/// Symbol: `FILTER`
	/// Type: Backtracking
	func parseFilterInternal() throws -> FilterExpression {
		let parseNext: () throws -> FilterListExpressionContinued = {
			try self.expect(token: .space)
			let logicalOperator = try self.parseLogicalOperator()
			try self.expect(token: .space)
			let filterOption = try self.parseFilterOption()
			return .init(logicalOperator: logicalOperator, filter: filterOption)
		}
		
		let filterOption = try parseFilterOption()
		var continued: [FilterListExpressionContinued] = []
		while let next = attemptParse({ try parseNext() }) {
			continued.append(next)
		}
		
		let filterList = FilterListExpression(start: filterOption, continued: continued)
		return filterList.toFilterExpression()
	}
	
	/// Parses a filter value from the grammar.
	///
	/// Symbol: `filterValue`
	/// Type: Backtracking
	func parseFilterOption() throws -> FilterValueExpression {
		if let attrExp = attemptParse({ try parseAttributeExpression() }) {
			// Try attrExp
			return .attributeExpression(attrExp)
		} else if let valuePath = attemptParse({ try parseValuePath() }) {
			// Try valuePath
			return .valuePathExpression(valuePath)
		} else {
			// Try ["not" [SP]] "(" valFilter ")"
			var isNegated = false
			if try attempt(token: .keywordIdentifier(.not)) {
				isNegated = true
				_ = try attempt(token: .space)
			}
			
			try expect(token: .openParen)
			let filter = try parseFilterInternal()
			try expect(token: .closeParen)
			
			if isNegated {
				return .negatedGroupedFilter(filter)
			} else {
				return .groupedFilter(filter)
			}
		}
	}
	
	/// Parses a value path from the grammar.
	/// Allows for a pre-parsed attribute path beginning symbol to be used.
	///
	/// Symbol: `valuePath`
	/// Type: Backtracking
	func parseValuePath(withPreParsedAttrPath preParsedAttrPath: AttributePath? = nil) throws -> ValuePathExpression {
		
		// Either use a pre-parsed attrPath, or parse it ourselves
		let attrPath: AttributePath
		if let preParsedAttrPath = preParsedAttrPath {
			attrPath = preParsedAttrPath
		} else {
			attrPath = try parseAttributePath()
		}
		
		try expect(token: .openBracket)
		let valFilter = try parseValueFilter()
		try expect(token: .closeBracket)
		
		return ValuePathExpression(attributePath: attrPath, valueFilterExpression: valFilter)
	}
	
	/// Parses a value filter from the grammar.
	///
	/// Symbol: `valFilter`
	/// Type: Backtracking
	func parseValueFilter() throws -> ValueFilterExpression {
		let parseNext: () throws -> ValueFilterListExpressionContinued = {
			try self.expect(token: .space)
			let logicalOperator = try self.parseLogicalOperator()
			try self.expect(token: .space)
			let valFilterOption = try self.parseValueFilterListOption()
			return .init(logicalOperator: logicalOperator, filter: valFilterOption)
		}
		
		let valFilterValue = try parseValueFilterListOption()
		var continued: [ValueFilterListExpressionContinued] = []
		while let next = attemptParse({ try parseNext() }) {
			continued.append(next)
		}
		
		let valueFilterList = ValueFilterListExpression(start: valFilterValue, continued: continued)
		return valueFilterList.toValueFilterExpression()
	}
	
	/// Parses a value filter expression from the grammar.
	///
	/// Symbol: `valFilterValue`
	/// Type: Backtracking
	func parseValueFilterListOption() throws -> ValueFilterValueExpression {
		if let attrExp = attemptParse({ try parseAttributeExpression() }) {
			// Try attrExp
			return .attributeExpression(attrExp)
		} else {
			// Try ["not" [SP]] "(" valFilter ")"
			var isNegated = false
			if try attempt(token: .keywordIdentifier(.not)) {
				isNegated = true
				_ = try attempt(token: .space)
			}
			
			try expect(token: .openParen)
			let valFilter = try parseValueFilter()
			try expect(token: .closeParen)
			
			if isNegated {
				return .negatedGroupedValueFilter(valFilter)
			} else {
				return .groupedValueFilter(valFilter)
			}
		}
	}
	
	/// Parses an attribute expression from the grammar.
	/// Allows for a pre-parsed attribute path beginning symbol to be used.
	///
	/// Symbol: `attrExp`
	/// Type: Backtracking
	func parseAttributeExpression() throws -> AttributeExpression {
		let attrPath = try parseAttributePath()
		
		_ = try expect(token: .space)
		
		if try attempt(token: .keywordIdentifier(.pr)) {
			return AttributeExpression.present(.init(attributePath: attrPath))
		} else if let compOp = attemptParse({ try parseComparativeOperator() }) {
			try expect(token: .space)
			let compValue = try parseComparativeValue()
			return AttributeExpression.comparison(.init(
				attributePath: attrPath,
				comparativeOperator: compOp,
				comparativeValue: compValue))
		} else {
			throw ParserError(message: "Expected an attribute operator at \(currentTokenIndex), but instead found a \(currentToken)")
		}
	}
}
