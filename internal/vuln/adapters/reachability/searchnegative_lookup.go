package reachability

import (
	"go/token"
	"sort"
	"strings"

	callgraphdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"

	"code.eitanity.com/kanonarion/internal/vuln/domain"
	"code.eitanity.com/kanonarion/internal/vuln/ports"
)

// lookupEdge is one edge the search added past a reflective method lookup.
type lookupEdge struct{ from, to string }

// searchPastLookups returns proj with an edge from each lookup site's caller to
// every method the lookup can return, the sites told whether the entry points
// reach them, and the site each added edge was added for.
//
// A site with a known name set (a constant MethodByName name, or the names a
// module's constant templates use) binds the exported methods of those names;
// any other site binds nothing. Only reachable sites add edges, and a method
// reached through one can reach a further site, so the reached set is
// recomputed until no site joins. Under a TinyGo whose reflect returns no
// method, a reached site binds nothing and says why.
func searchPastLookups(proj ports.CallGraphProjection, entryRoots []string) (ports.CallGraphProjection, []domain.ReflectiveDispatchSite, map[lookupEdge]domain.ReflectiveDispatchSite) {
	if len(proj.ReflectiveDispatch) == 0 {
		return proj, nil, nil
	}
	noMethod := proj.TinyGoTarget != "" && domain.TinyGoReflectReturnsNoMethod(proj.TinyGoVersion)
	byName := exportedMethods(proj)
	called := make(map[lookupEdge]bool, len(proj.Edges))
	for _, e := range proj.Edges {
		called[lookupEdge{e.FromID, e.ToID}] = true
	}

	aug := proj
	aug.Edges = append(make([]ports.CallGraphEdge, 0, len(proj.Edges)), proj.Edges...)
	added := map[lookupEdge]domain.ReflectiveDispatchSite{}
	sites := make([]domain.ReflectiveDispatchSite, len(proj.ReflectiveDispatch))
	reached := reachableFrom(aug, entryRoots)
	for grew := true; grew; {
		grew = false
		for i, s := range proj.ReflectiveDispatch {
			if sites[i].ReachableFromEntryPoint || !reached[s.CallerID] {
				continue
			}
			bound := methodsFor(s, byName, noMethod)
			sites[i] = siteOf(s)
			sites[i].ReachableFromEntryPoint = true
			sites[i].ReturnsNoMethod = noMethod
			sites[i].MethodsBound = len(bound)
			for _, m := range bound {
				key := lookupEdge{s.CallerID, m}
				if _, dup := added[key]; dup || called[key] {
					continue
				}
				added[key] = sites[i]
				aug.Edges = append(aug.Edges, ports.CallGraphEdge{FromID: s.CallerID, ToID: m})
			}
			grew = true
		}
		if grew {
			reached = reachableFrom(aug, entryRoots)
		}
	}
	for i, s := range proj.ReflectiveDispatch {
		if !sites[i].ReachableFromEntryPoint {
			sites[i] = siteOf(s)
		}
	}
	sortSites(sites)
	return aug, sites, added
}

// methodsFor is every method a reached site's lookup can return: none under a
// TinyGo whose reflect returns no method, else the exported ones of its names.
func methodsFor(s ports.CallGraphReflectSite, byName map[string][]string, noMethod bool) []string {
	if noMethod {
		return nil
	}
	var bound []string
	names, _ := callgraphdomain.LookupNames(s.LookupName)
	for _, name := range names {
		bound = append(bound, byName[name]...)
	}
	return bound
}

// siteOf is the reported form of a site, not yet told whether it is reached.
func siteOf(s ports.CallGraphReflectSite) domain.ReflectiveDispatchSite {
	names, bound := callgraphdomain.LookupNames(s.LookupName)
	return domain.ReflectiveDispatchSite{
		Caller: s.CallerID, Callee: s.CalleeID, CallSite: reflectSitePosition(s),
		LookupName: s.LookupName, Bound: bound, NameCount: len(names),
	}
}

// exportedMethods is every method node a lookup can return, by name: a
// receiver, an exported name that is not a closure's, and not test code.
func exportedMethods(proj ports.CallGraphProjection) map[string][]string {
	byName := map[string][]string{}
	for _, n := range proj.Nodes {
		if n.Receiver == "" || n.IsTest || !token.IsExported(n.Symbol) || strings.Contains(n.Symbol, "$") {
			continue
		}
		byName[n.Symbol] = append(byName[n.Symbol], n.ID)
	}
	return byName
}

// sortSites orders the sites on every field that distinguishes two: two calls
// from one function to one lookup differ only in their line.
func sortSites(sites []domain.ReflectiveDispatchSite) {
	sort.Slice(sites, func(i, j int) bool {
		a, b := sites[i], sites[j]
		if a.Caller != b.Caller {
			return a.Caller < b.Caller
		}
		if a.Callee != b.Callee {
			return a.Callee < b.Callee
		}
		if a.CallSite != b.CallSite {
			return a.CallSite < b.CallSite
		}
		return a.LookupName < b.LookupName
	})
}

// annotateLookupHops marks each hop of route that path reached over an edge
// added past a lookup, naming the site the edge was added for.
func annotateLookupHops(route domain.ReachabilityRoute, path []string, added map[lookupEdge]domain.ReflectiveDispatchSite) domain.ReachabilityRoute {
	for i := 1; i < len(path) && i < len(route); i++ {
		if site, ok := added[lookupEdge{path[i-1], path[i]}]; ok {
			route[i].Dispatch = domain.LookupHopDispatch(site)
		}
	}
	return route
}
