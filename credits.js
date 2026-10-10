// Shared by every page so the credits and licence wording lives in one place.
document.body.insertAdjacentHTML("beforeend", `
  <dialog id="credits-modal" class="modal" aria-labelledby="credits-modal-title" aria-describedby="credits-modal-desc">
    <div class="modal-dialog">
      <div class="modal-head">
        <h2 id="credits-modal-title">Credits and licence</h2>
        <button id="credits-close" class="modal-close" type="button" aria-label="Close dialog">&times;</button>
      </div>
      <div id="credits-modal-desc" class="modal-desc">
        <p>Much of the product, file path, domain and IP address data comes from <a href="https://github.com/magicsword-io/LOLRMM" target="_blank" rel="noopener noreferrer">LOLRMM (Living Off the Land RMM) <span aria-hidden="true">↗</span></a> by magicsword-io and its contributors. It is used under the <a href="./LOLRMM-LICENSE.txt" target="_blank" rel="noopener">Apache License 2.0</a>.</p>
        <p>This data has been modified. Entries were grouped and renamed into products, some were added or changed, and the result was converted into a WDAC policy and Defender IOC CSVs. These changes are not the work of the LOLRMM project.</p>
        <p>This tool is independent. It is not affiliated with, endorsed by or supported by LOLRMM, magicsword-io or the vendors of the software listed. Product names and trademarks belong to their respective owners and are used only to identify the software.</p>
        <p>The data and policies are provided "as is", without warranty of any kind. Lists can be incomplete or out of date. Review the rules and test on pilot devices before you deploy them.</p>
      </div>
    </div>
  </dialog>`);

const modal = document.getElementById("credits-modal");
document.getElementById("credits-open").addEventListener("click", () => modal.showModal());
document.getElementById("credits-close").addEventListener("click", () => modal.close());
// A click on the dialog element itself lands on the backdrop, outside the content box.
modal.addEventListener("click", event => {
  if (event.target === modal) modal.close();
});
